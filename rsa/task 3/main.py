from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

from rsa_no_pss import generate_keypair, DebugRNG, RSASSA_PSS_SIGN

from keys import DEBUG_PRIV_KEY, DEBUG_PUB_KEY


key = RSA.construct((DEBUG_PUB_KEY[0], DEBUG_PUB_KEY[1], DEBUG_PRIV_KEY[1]))

# predictable randomness for debugging purposes
debug_rng = DebugRNG()

msg = b"ciao come stai"

sig1 = pss.new(key, salt_bytes=32, rand_func=lambda len: debug_rng.next(len)).sign(
    SHA256.new(msg)
)

sig2 = RSASSA_PSS_SIGN(DEBUG_PRIV_KEY, msg, debug_rng)

assert sig1 == sig2
