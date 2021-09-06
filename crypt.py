from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import os

"""Functions useful across several challenges or sets"""

AES_BS_b = 128
AES_BS_B = AES_BS_b // 8


class PaddingLengthError(Exception):
    """Input data was not correctly padded to the block size"""


class PaddingValueError(Exception):
    """Input data was not correctly padded to the block size"""


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
        count += sum([1 for bit in bin(diff) if bit == "1"])
    return count


def rand_key(size: int = AES_BS_B) -> bytes:
    return os.urandom(size)


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def pkcs7_pad(msg: bytes, blocksize=AES_BS_B) -> bytes:
    padding_len = blocksize - len(msg) % blocksize
    padding = bytes([padding_len]) * padding_len
    return msg + padding


def pkcs7_unpad(msg: bytes, blocksize=AES_BS_B) -> bytes:
    if not len(msg) % blocksize == 0:
        raise PaddingLengthError

    last_value = msg[-1]
    last_value_int = int(last_value)
    check_count = 0
    for char in reversed(msg):
        if char == last_value:
            check_count += 1
        else:
            break

    if not check_count == last_value_int:
        raise PaddingValueError

    return msg[:-last_value_int]


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    plaintext = pkcs7_pad(plaintext, AES_BS_B)
    return aes_encrypt(plaintext, key)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    plaintext = aes_decrypt(ciphertext, key)
    return pkcs7_unpad(plaintext)


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    blocks = [plaintext[i : i + AES_BS_B] for i in range(0, len(plaintext), AES_BS_B)]
    prev_block_cipher = None

    for block in blocks:
        if prev_block_cipher:
            cbc_block = fixed_xor(block, prev_block_cipher)
        else:
            cbc_block = fixed_xor(block, iv)

        cipher_block = aes_encrypt(cbc_block, key)
        prev_block_cipher = cipher_block
        ciphertext.extend(cipher_block)

    return ciphertext


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    blocks = [ciphertext[i : i + AES_BS_B] for i in range(0, len(ciphertext), AES_BS_B)]
    plaintext = bytearray()

    for i, cipher_block in enumerate(blocks):
        cbc_block = aes_decrypt(cipher_block, key)
        if i == 0:
            plain_block = fixed_xor(cbc_block, iv)
        else:
            plain_block = fixed_xor(cbc_block, blocks[i - 1])
        plaintext.extend(plain_block)

    plaintext_unpadded = pkcs7_unpad(plaintext)
    return plaintext_unpadded
