from Crypto.Cipher import AES
import requests
import sys
from typing import Iterator
from copy import copy, deepcopy
from Crypto.Util.Padding import pad
import tqdm


COOKIE = "5d1a3cdb89983a98a8996b1c8d94e666f31abafa089e4fe59dc1265280083802ef8fb5ce742ccc0cff8f669de77bb71d7bdde8a5257f73ed77334a64ecc7ad48c2c7372e44dc8ad617165e4f564a7ec00455a2c674ab7728f007a9bc8f4bcd5bf19e0a1dd0b3d7de17467dc1f24ebbb0"

BLOCK_SIZE = 16


class Oracle:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def correct_padding(self, cookie: bytes) -> bool:
        res = requests.get(
            f"{base_url}/quote/", cookies={"authtoken": cookie.hex()}
        ).text
        return "incorrect" not in res


def get_response(base_url, cookie: bytes):
    res = requests.get(f"{base_url}/quote/", cookies={"authtoken": cookie.hex()})
    return res.text


def correct_padding(base_url, ciphertext: bytes) -> bool:
    """Check if the ciphertext is padded correctly"""
    return "No quote for you!" in get_response(base_url, ciphertext)


def get_block(stream: bytes, block_num) -> bytes:
    """Get nth block from the end"""
    start = -((block_num + 1) * BLOCK_SIZE)
    end = -(block_num * BLOCK_SIZE) if block_num != 0 else None
    return stream[start:end]


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


def replace_plain_byte(
    cipher_block: bytes, index: int, old_val: int, new_val: int
) -> bytes:
    """Replace a known plaintext byte with a new one, without decryption"""
    assert index < BLOCK_SIZE
    assert len(cipher_block) == BLOCK_SIZE
    old_encrypted = get_byte(cipher_block, index)
    key = old_encrypted ^ old_val
    new_encrypted = key ^ new_val
    return set_byte(cipher_block, index, new_encrypted)


def xor_blocks(lhs: bytes, rhs: bytes) -> bytes:
    assert len(lhs) == len(rhs) == BLOCK_SIZE
    res = b"".join(((b1 ^ b2).to_bytes() for b1, b2 in zip(lhs, rhs)))
    assert len(res) == BLOCK_SIZE
    return res


def xor_bytes(lhs: bytes, rhs: bytes) -> bytes:
    assert len(lhs) == len(rhs)
    return b"".join(((b1 ^ b2).to_bytes() for b1, b2 in zip(lhs, rhs)))


def replace_plain_block(block_crypt, block_old, block_new):
    assert len(block_crypt) == len(block_old) == len(block_new)
    key = xor_blocks(block_crypt, block_old)
    return xor_blocks(block_new, key)


def gen_padding(num: int) -> bytes:
    assert num <= BLOCK_SIZE
    tail = num.to_bytes() * num
    prefix = b"\x00" * (BLOCK_SIZE - num)
    res = prefix + tail
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


def crack_block_key(oracle: Oracle, block: bytes):
    assert len(block) == BLOCK_SIZE

    # all block and byte indexes are reversed, they are from the end, this
    # makes it easier to think about since everything has to be done from the
    # back!

    # initial guess of key should be neutral for math reasons
    dec_key = b"\x00" * BLOCK_SIZE
    c2 = block

    # tqdm does progress bars :)
    for byte_offset in tqdm.tqdm(range(BLOCK_SIZE), leave=False, desc="bytes in block"):
        # padding = gen_padding(byte_offset + 1)
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


# def crack_block(base_url, ciphertext: bytes, block_num: int):
#     """Given cyphertext and index of plaintext block from the end, cracks the
#     decryption key block"""

#     # initial guess of key should be neutral for math reasons
#     dec_key = b"\x00" * 16
#     c1 = get_block(ciphertext, block_num + 1)
#     c2 = get_block(ciphertext, block_num)
#     for i in range(16):
#         # base case: first byte is sligthly different
#         if i == 0:
#             for guess in range(256):
#                 modified_c1 = replace_plain_byte(c1, 0, guess, 0x1)
#                 if correct_padding(base_url, modified_c1 + c2):
#                     # we might be in an edge case, where the last byte is 0x2
#                     # in this case, query should fail if penultimate byte is
#                     # set to something else
#                     penultimate = get_byte(modified_c1, 1)
#                     penultimate = (penultimate + 1) % 256
#                     modified_c1 = set_byte(modified_c1, 1, penultimate)
#                     if correct_padding(base_url, modified_c1 + c2):
#                         # we found the zeroing byte
#                         c1_byte = get_byte(c1, 0)
#                         key_byte = c1_byte ^ guess
#                         dec_key = set_byte(dec_key, 0, key_byte)
#                         plain = set_byte(plain, 0, guess)
#                         continue
#         else:
#             # set the tail using the recovered key
#             for guess in range(256):
#                 pass


# def single_block_attack(block, oracle: Oracle):
#     """Returns the decryption of the given ciphertext block"""

#     # zeroing_iv starts out nulled. each iteration of the main loop will add
#     # one byte to it, working from right to left, until it is fully populated,
#     # at which point it contains the result of DEC(ct_block)
#     dec_key = b"\x00" * BLOCK_SIZE
#     c2 = block

#     for byte_offset in range(BLOCK_SIZE):
#         padding = (byte_offset + 1).to_bytes() * BLOCK_SIZE
#         c1 = xor_blocks(padding, dec_key)
#         # c1 = [(byte_offset + 1) ^ b for b in dec_key]

#         for byte_guess in range(256):
#             c1_candidate = set_byte(c1, byte_offset, byte_guess)
#             print(c1_candidate.hex("_"))
#             iv = c1_candidate
#             if oracle.correct_padding(iv + c2):
#                 if byte_offset == 0:
#                     # make sure the padding really is of length 1 by changing
#                     # the penultimate block and querying the oracle again
#                     c1_penultimate = get_byte(c1_candidate, 1)
#                     c1_penultimate = (c1_penultimate + 1) % 256
#                     c1_nudged = set_byte(c1_candidate, 1, c1_penultimate)
#                     if not oracle.correct_padding(c1_nudged + c2):
#                         continue  # false positive; keep searching
#                 break
#         else:
#             raise Exception(
#                 "no valid padding byte found (is the oracle working correctly?)"
#             )
#         dec_key = set_byte(dec_key, byte_offset, byte_guess ^ (byte_offset + 1))

#     return [b for b in dec_key]


def full_attack(iv, ct, oracle: Oracle):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    print("forward attack...")

    msg = iv + ct
    blocks = blockify(msg)
    result = b""

    # loop over pairs of consecutive blocks performing CBC decryption on them
    iv = blocks[0]
    dec_key = []
    for ct in tqdm.tqdm(blocks[1:], leave=False, desc="blocks in message"):
        dec = [b for b in crack_block_key(oracle, ct)]
        dec_key.append(dec)
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += pt
        iv = ct

    dec_key = [bytes(k) for k in dec_key]
    return result, dec_key


# https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf
def reverse_attack(oracle: Oracle, pt: bytes) -> bytes:
    # step 1
    pt_blocks = blockify(pt)
    N = len(pt_blocks)

    # step 2
    ct = [b"\x00" * BLOCK_SIZE] * N
    ct[N - 1] = random_block()

    # step 3
    for i in range(N - 1, 0, -1):
        dec_key = crack_block_key(oracle, ct[i])
        ct[i - 1] = xor_blocks(pt_blocks[i], dec_key)

    # step 4
    dec_key = crack_block_key(oracle, ct[0])
    iv = xor_blocks(pt_blocks[0], dec_key)

    # step 5
    res = b"".join([iv] + ct)
    assert len(res) == len(pt) + BLOCK_SIZE
    return res


def reverse_attack_old(
    new_plain: bytes, dec_key: list[bytes], final_block: bytes
) -> bytes:
    # construct a new cyphertext backwards using a recovered decryption key
    # and the final block of the original ciphertext
    assert len(final_block) == BLOCK_SIZE

    ct_rev = [final_block]
    key_rev = copy(dec_key)
    key_rev.reverse()
    pt_blocks_rev = [
        new_plain[i : i + BLOCK_SIZE] for i in range(0, len(new_plain), BLOCK_SIZE)
    ]
    pt_blocks_rev.reverse()

    for pt_block, key_block in zip(pt_blocks_rev, key_rev):
        new_ct = xor_blocks(pt_block, key_block)
        ct_rev.append(new_ct)

    ct_rev.reverse()
    return b"".join(ct_rev)


# TODO: read from arg
cookie = bytes.fromhex(COOKIE)
base_url = "http://localhost:5000"
num_blocks = len(cookie) // 16

iv = cookie[:16]
oracle = Oracle(base_url)


ct_forged = reverse_attack(
    oracle,
    pad(
        b"I should have used authenticated encryption because ... plain CBC is not secure!",
        BLOCK_SIZE,
    ),
)
print(get_response(base_url, ct_forged))

# plain, key = full_attack(
#     iv,
#     cookie[16:],
#     oracle,
# )
# print(f"recovered plaintext: {plain}")
# new_plain = pad(
#     b"I should have used authenticated encryption because ... plain CBC is not secure!",
#     BLOCK_SIZE,
# )
