from abc import ABC, abstractmethod
import hashlib
from Crypto.Signature.pss import MGF1
from Crypto.Hash import SHA256
import Crypto
import os
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import getPrime
import random
import math
from Crypto.Signature import pss

from Crypto.Hash import SHA256

from Crypto.PublicKey import RSA

#################################################################################################
# generazione chiavi
#################################################################################################


def generate_keypair(bits):
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p != q:
            n = p * q
            if n.bit_length() == bits:
                phi = (p - 1) * (q - 1)
                e = 65537
                if e < phi and phi % e != 0:  # i am checking if e and phi are coprime
                    d = modinv(e, phi)
                    # print("phi:",phi)
                    # print("d:",d)
                    return ((n, e), (n, d))


def modinv(
    a, m
):  # Euclidean algorithm in order to compute the modular multiplicative inverse
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


#################################################################################################
# signature
#################################################################################################


class RNG(ABC):
    @abstractmethod
    def next(self, len: int) -> bytes:
        pass


class DebugRNG(RNG):
    def next(self, len: int) -> bytes:
        res = []
        for i in range(len):
            res.append(i)
        return bytes(res)


class SafeRNG(RNG):
    def next(self, len: int) -> bytes:
        return os.urandom(len)


def OS2IP(X: bytes) -> int:
    return int.from_bytes(X, "big")


def RSASP1(K, m):
    if not (0 <= m < K[0]):  # check if the message id between 0 and n-1
        raise ValueError("message representative out of range")

    n, d = K
    s = pow(m, d, n)

    return s


def I2OSP(x: int, xLen: int) -> bytes:
    return x.to_bytes(xLen, "big")


def EMSA_PSS_ENCODE(M, emBits, rng: RNG):
    emLen = math.ceil(emBits / 8)
    hlen = 32  # byte the length in octets of hash256
    slen = 32  # byte the lenght of the salt
    # step 1
    # hash256 doesn't have input limitations

    # step 2
    mHash = SHA256.new(M).digest()

    # step 3
    if emLen < (hlen + slen + 2):
        raise ValueError("Encoding error")

    # step 4
    salt = rng.next(slen)

    # step 5
    m_prime = b"\x00" * 8 + mHash + salt

    # step 6
    H = SHA256.new(m_prime).digest()

    # step 7
    PS_len = emLen - slen - hlen - 2
    if PS_len == 0:  # i am not sure about the if
        PS = b""
    else:
        PS = b"\x00" * PS_len

    # step 8
    DB = PS + b"\x01" + salt

    # step 9
    # dbMask = MGF1(DB, emLen - hlen - 1, SHA256)
    dbMask = MGF1(H, emLen - hlen - 1, SHA256)

    # step 10
    maskedDB = bytearray()
    for b1, b2 in zip(DB, dbMask):
        maskedDB.append(b1 ^ b2)

    # step 11
    leading_zero_bits = 8 * emLen - emBits
    # Get the leftmost octet
    leftmost_octet = maskedDB[0]
    # Set the leftmost bits to zero using bitwise AND
    leftmost_octet &= 0xFF >> leading_zero_bits
    # Update the maskedDB
    maskedDB = bytes([leftmost_octet]) + maskedDB[1:]

    # step 12
    EM = maskedDB + H + b"\xbc"

    return EM


def RSASSA_PSS_SIGN(private_key, message, rng: RNG):
    modBits = 3072  # the length in bits of the RSA modulus n
    # step 1
    em = EMSA_PSS_ENCODE(message, modBits - 1, rng)
    # print("rsa_pss: ",em)
    # step 2a
    m = OS2IP(em)

    # step 2b
    s = RSASP1(private_key, m)

    # step 2c
    k = 3072 // 8  # the length in octets of the RSA modulos n
    # print("s: ",s)
    # print("k",k)
    S = I2OSP(s, k)
    return S


#################################################################################################
# verification
#################################################################################################


def RSAVP1(public_key, S):
    n, e = public_key
    # Check if the signature representative is within the range [0, n - 1]
    if not (0 <= S < n):
        return "signature representative out of range"

    # Compute the message representative m
    m = pow(S, e, n)

    return m


def verification(M, EM, emBits):
    emLen = math.ceil(emBits / 8)
    hlen = 32  # byte the length in octets of hash256
    slen = 32  # byte the lenght of the salt
    # step 1
    # step 2
    mHash = SHA256.new(M).digest()

    # step 3
    if emLen < (hlen + slen + 2):
        raise ValueError("Encoding error")

    # step 4
    rightmost_octet = EM[-1]

    # Check if the rightmost octet is not equal to "bc" in hexadecimal
    if rightmost_octet != 0xBC:
        print("exit a")
        return "inconsistent"

    # step 5
    maskedDB = EM[: emLen - hlen - 1]
    H = EM[emLen - hlen - 1 : emLen - hlen - 1 + hlen]

    # step 6
    leading_zero_bits = 8 * emLen - emBits
    first_byte = maskedDB[0]

    # Maschera il primo bit
    first_bit_masked = first_byte & 0b10000000  # Maschera per il primo bit

    # Controlla se il primo bit è zero
    if first_bit_masked != 0:
        print("exit b")
        print("Il primo bit del primo byte non è zero.")
        return "inconsistent"

    # step 7
    dbMask = MGF1(H, emLen - hlen - 1, SHA256)

    # step 8
    DB = bytearray()
    for b1, b2 in zip(maskedDB, dbMask):
        DB.append(b1 ^ b2)

    # step 9
    leading_zero_bits = 8 * emLen - emBits
    # Get the leftmost octet
    leftmost_octet = DB[0]
    # Set the leftmost bits to zero using bitwise AND
    leftmost_octet &= 0xFF >> leading_zero_bits
    # Update the maskedDB
    DB = bytes([leftmost_octet]) + DB[1:]

    # step 10
    position = emLen - hlen - slen - 2
    print()
    print()
    print()
    print(DB)
    print("position: ", position)
    print("debag: ", DB[position - 1])
    if DB[:position] != bytes([0] * position):
        print("exit c")
        return "inconsistent"
    if DB[emLen - hlen - slen - 1] != 0x01:
        print("exit cccc")
        return "inconsistent"

    # step 11
    salt = DB[-slen:]

    # step 12
    m_prime = b"\x00" * 8 + mHash + salt

    # step 13
    H_prime = SHA256.new(m_prime).digest()

    # step 14
    if H == H_prime:
        print("exit d")
        return "consistent"
    else:
        print("exit e")
        return "inconsistent"


def RSASSA_PSS_VERIFY(public_key, M, S):
    # Length checking
    k = 3072 / 8
    if len(S) != k:
        return "invalid signature"

    # Convert signature to integer
    s = OS2IP(S)

    # RSA verification
    m = RSAVP1(public_key, s)
    if m == "signature representative out of range":
        return "invalid signature"

    # Convert message representative to encoded message
    modBits = public_key[0].bit_length()
    emLen = math.ceil((modBits - 1) / 8)
    # print("m: ", m)
    # print("emLen: ", emLen)
    try:
        EM = I2OSP(m, emLen)
    except ValueError:
        return "invalid signature"

    # EMSA-PSS verification
    modBits = 3072
    Result = verification(M, EM, modBits - 1)

    if Result == "consistent":
        return "valid signature"
    else:
        return "invalid signature"


if __name__ == "__main__":
    # public_key = (n, e)
    # private_key = (n, d)
    public_key, private_key = generate_keypair(3072)
    print("n: ", public_key[0])
    print("e: ", public_key[1])
    print("d: ", private_key[1])
    rng = SafeRNG()
    message = b"ciao come stai"
    signature = RSASSA_PSS_SIGN(private_key, message, rng)
    print(signature)
    """h = SHA256.new(message)

    verifier = pss.new(public_key[0])

    try:

        verifier.verify(h, signature)

        print("The signature is authentic.")

    except (ValueError):

        print("The signature is not authentic.") """
    # controllare la firma
    key = Crypto.PublicKey.RSA.construct(public_key)
    prova = pss.new(key).verify(SHA256.new(message), signature)
    # verifica = verify(signature, public_key[1], public_key[0], message)
    # print(verifica)
    # verify = RSASSA_PSS_VERIFY(public_key, message, signature)
    # print("esito: ", verify)
