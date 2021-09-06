from base64 import b64encode, b64decode

"""Functions useful across several challenges or sets"""


def hex_to_base64(msg: str) -> str:
    return b64encode(bytes.fromhex(msg)).decode("utf-8")


def base64_to_hex(msg: str) -> str:
    return b64decode(msg).hex()


def fixed_xor(a: bytes, b: bytes) -> bytes:
    return bytes([a ^ b for (a, b) in zip(a, b)])


def sxor(a: str, b: str) -> str:
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(a, b))


def english_score(msg: str) -> float:
    msg = msg.lower()
    character_frequencies = {
        "a": 0.08167,
        "b": 0.01492,
        "c": 0.02782,
        "d": 0.04253,
        "e": 0.12702,
        "f": 0.02228,
        "g": 0.02015,
        "h": 0.06094,
        "i": 0.06094,
        "j": 0.00153,
        "k": 0.00772,
        "l": 0.04025,
        "m": 0.02406,
        "n": 0.06749,
        "o": 0.07507,
        "p": 0.01929,
        "q": 0.00095,
        "r": 0.05987,
        "s": 0.06327,
        "t": 0.09056,
        "u": 0.02758,
        "v": 0.00978,
        "w": 0.02360,
        "x": 0.00150,
        "y": 0.01974,
        "z": 0.00074,
        " ": 0.13000,
    }

    score = sum([character_frequencies.get(char, 0) for char in msg])
    for char in msg:
        if not char.isalpha():
            score -= 0.1
        if char == "\n":
            score -= 0.2
    return score


def single_xor_cipher(msg: bytes, key: int) -> tuple[bytes, float]:
    # Inverse of XOR is XOR
    xor = bytes(a ^ key for a in msg)
    return xor, english_score(str(xor, "utf-8"))


def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    xor = []
    key_len = len(key)
    for i, byte in enumerate(plaintext):
        xor.append(byte ^ key[i % key_len])
    return bytes(xor)

def hamming_distance(a: bytes, b: bytes) -> int:
    count = 0
    for x, y in zip(a, b):
        diff = x ^ y
        count += sum([1 for bit in bin(diff) if bit == '1'])
    return count
