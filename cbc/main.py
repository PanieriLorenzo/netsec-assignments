from Crypto.Cipher import AES
import requests
import sys
from typing import Iterator
from copy import copy, deepcopy


COOKIE = "5d1a3cdb89983a98a8996b1c8d94e666f31abafa089e4fe59dc1265280083802ef8fb5ce742ccc0cff8f669de77bb71d7bdde8a5257f73ed77334a64ecc7ad48c2c7372e44dc8ad617165e4f564a7ec00455a2c674ab7728f007a9bc8f4bcd5bf19e0a1dd0b3d7de17467dc1f24ebbb0"


def hex2bytes(text: str) -> bytearray:
    return bytearray(bytes.fromhex(text))


def bytes2hex(bytes: bytearray) -> str:
    """Convert reversed bytearray to hex"""
    return bytes.hex()


def set_byte(ciphertxt: bytearray, idx: int, byte: int):
    pass


# TODO: read from arg
cookie = hex2bytes(COOKIE)
num_blocks = len(cookie) // 16
plaintext = []


exit(0)
# ==== NOTE: below are failed attempts, they don't work ====

def crack_block(
    remaining_ciphertext: bytearray, processed_ciphertext: bytearray
) -> bytearray:
    """Cracks the last block of the cookie ciphertext"""
    remaining_ciphertext = deepcopy(remaining_ciphertext)
    processed_ciphertext = deepcopy(processed_ciphertext)

    # move final block of the ciphertext to processed
    processed_ciphertext = remaining_ciphertext[-16:] + processed_ciphertext
    remaining_ciphertext = remaining_ciphertext[:-16]

    # if the ciphertext is empty, we have reached the start of the message,
    # crack using an initialization vector
    if len(remaining_ciphertext) == 0:
        raise NotImplementedError
        # TODO: return crack_iv(ciphertext)

    # get the second last block in the ciphertext
    ciphertext_block = remaining_ciphertext[-16:]
    remaining_ciphertext = remaining_ciphertext[:-16]

    # find the bytes in the plaintext one by one
    plaintext = []
    for i in range(16):
        for g, modified_block in iter_block_guesses(ciphertext_block, i):
            if correct_padding(
                remaining_ciphertext + modified_block + processed_ciphertext
            ):
                plaintext.append(g)
                break
    # assert len(plaintext) == 16

    # reverse the plaintext, as we guess from the end to the beginning
    plaintext = plaintext[::-1]
    print(plaintext)


def iter_blocks(cookie: bytearray) -> Iterator[bytearray]:
    for i in range(len(cookie) // 16):
        yield deepcopy(cookie[i * 16 : (i + 1) * 16])


def iter_block_guesses(
    cipher_block: bytearray, byte_idx: int
) -> Iterator[tuple[int, bytearray]]:
    """Given a ciphertext block and a byte index, iterates over guesses for
    byte at index"""
    cipher_block = deepcopy(cipher_block)
    for g in range(255):
        cipher_block[byte_idx] ^= g ^ 0x1
        yield (g, cipher_block)


def attack_old():
    guess = list(iter_blocks(COOKIE))
    print(len(guess))
    for block_idx in range(NUM_BLOCKS - 1, 1, -1):
        for byte_idx in range(15, 0, -1):
            found = False
            for b in range(256):
                new_block = bytearray(guess[block_idx])
                new_block[byte_idx] = b
                new_block = bytes(new_block)
                new_guess = guess[:block_idx] + [new_block] + guess[block_idx + 1 :]
                if "quote" in get_response(
                    "http://localhost:5000", b"".join(new_guess)
                ):
                    guess = new_guess
                    found = True
                    break
            if found:
                break
    test_systems_security("http://localhost:5000", b"".join(guess))

    # for b in range(256):
    #     new_guess = [copy(g) for g in guess]
    #     new_guess = (
    #         new_guess[:-2] + [new_guess[-2][:-1] + b.to_bytes(1)] + [new_guess[-1]]
    #     )
    #     test_systems_security("http://localhost:5000", b"".join(new_guess))


def get_response(base_url, cookie: bytes):
    res = requests.get(f"{base_url}/quote/", cookies={"authtoken": cookie.hex()})
    return res.text


def correct_padding(ciphertext: bytearray) -> bool:
    """Check if the ciphertext is padded correctly"""
    return "quote" in get_response("http://localhost:5000", bytes(ciphertext))


def test_systems_security(base_url, cookie: bytes):
    res = requests.get(f"{base_url}/quote/", cookies={"authtoken": cookie.hex()})
    print(f"[+] done:\n{res.text}")


crack_block(bytearray(COOKIE[:-16]), bytearray(b""))
