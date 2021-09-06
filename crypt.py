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


def english_score(msg: str) -> float:
    msg = msg.lower()
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253, 'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094, 'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025, 'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929, 'q': .00095, 'r': .05987, 's': .06327, 't': .09056, 'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150, 'y': .01974, 'z': .00074, ' ': .13000
    }

    score = sum([character_frequencies.get(char, 0) for char in msg])
    for char in msg:
        if not char.isalpha():
            score -= 0.1
        if char == '\n':
            score -= 0.2
    return score


def single_xor_cipher(msg: bytes, key: int) -> tuple[bytes, float]:
    # Inverse of XOR is XOR
    xor = bytes(a ^ key for a in msg)
    return xor, english_score(str(xor, "utf-8"))
