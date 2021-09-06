from base64 import b64encode, b64decode

"""Functions useful across several challenges or sets"""


def hex_to_base64(msg: str) -> str:
    return b64encode(bytes.fromhex(msg)).decode("utf-8")


def base64_to_hex(msg: str) -> str:
    return b64decode(msg).hex()


def fixed_xor(a: bytes, b: bytes) -> bytes:
    return bytes([a ^ b for (a, b) in zip(a, b)])


def sxor(a: str, b: str) -> str:
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(a, b))
