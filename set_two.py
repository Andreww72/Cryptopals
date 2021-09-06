import math
import crypt
import random
from base64 import b64decode

AES_BS_B = crypt.AES_BS_B

"""
Set 2 of Cryptopals
https://cryptopals.com/sets/2
"""


def challenge_9() -> None:
    """Implement PKCS#7 padding
    https://cryptopals.com/sets/2/challenges/9"""

    padded = crypt.pkcs7_pad(b"YELLOW SUBMARINE")
    unpadded = crypt.pkcs7_unpad(padded)
    print(f"{padded=}")
    print(f"{unpadded=}")

    padded = crypt.pkcs7_pad(b"this is a sentence to test padding")
    unpadded = crypt.pkcs7_unpad(padded)
    print(f"{padded=}")
    print(f"{unpadded=}")


def challenge_10() -> None:
    """Implement CBC mode
    https://cryptopals.com/sets/2/challenges/10"""

    # Test decrypting given data
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * AES_BS_B

    with open("data/set2_ch10_data.txt", "r") as f:
        ciphertext = b64decode(f.read().strip())
        ch8 = crypt.aes_cbc_decrypt(ciphertext, key, iv)
        print(f"{ch8=}")

    # Test encrypt then decrypt
    message = b"Three can keep a secret, if two of them are dead"
    key = crypt.rand_key()
    iv = crypt.rand_key()
    encrypted = crypt.aes_cbc_encrypt(message, key, iv)
    decrypted = crypt.aes_cbc_decrypt(encrypted, key, iv)

    # Check results
    print(message)
    print(decrypted)


def challenge_11() -> None:
    """ECB/CBC detection oracle
    https://cryptopals.com/sets/2/challenges/11"""

    def rand_encrypt(plaintext: bytearray) -> bytes:
        key = crypt.rand_key()
        encr_type = random.randint(0, 1)

        # Prepend and postpend 5-10 bytes to plaintext here
        prepend_len = random.randint(5, 10)
        postpend_len = random.randint(5, 10)

        for i in range(prepend_len):
            plaintext = bytearray(plaintext)
            plaintext.insert(0, random.randint(0, 128))
        for i in range(postpend_len):
            plaintext.append(random.randint(0, 128))

        if encr_type:
            print("Using: ECB")
            return crypt.aes_ecb_encrypt(plaintext, key)
        else:
            print("Using: CBC")
            iv = crypt.rand_key()
            return crypt.aes_cbc_encrypt(plaintext, key, iv)

    def encryption_oracle(plaintext: bytes) -> str:
        # Four blocks because first and last edited by the prepend and postpend
        # Send rand_encrypt repetitive data
        ciphertext = rand_encrypt(bytearray(plaintext))

        # Check ciphertext for repetitive output
        # Repeats means ECB, otherwise CBC
        blocks = [
            ciphertext[i : i + AES_BS_B] for i in range(0, len(ciphertext), AES_BS_B)
        ]
        repeater = set()
        for block in blocks:
            repeater.add(bytes(block))

        if len(repeater) == len(blocks):
            return "CBC"
        else:
            return "ECB"

    # Run test with defined functions
    for i in range(0, 5):
        print("Detected: " + encryption_oracle(b"A" * 16 * 4))


def challenge_12() -> None:
    """Byte-at-a-time ECB decryption (simple)
    https://cryptopals.com/sets/2/challenges/12"""

    class InvalidECBMode(Exception):
        """Cipher not using ECB"""

    class ECB_Oracle:
        def __init__(self):
            self.key = crypt.rand_key()

        def encrypt(self, append_known: bytes, ciphertext: bytes):
            return crypt.aes_ecb_encrypt(append_known + ciphertext, self.key)

    data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    unknown = b64decode(data)
    ecb_oracle = ECB_Oracle()

    # Discover the block size of the cipher (use your-string only)
    blocksize = len(ecb_oracle.encrypt(b"A", b""))
    print(f"{blocksize=} bytes")

    # Detect if function is using ECB
    test_ecb = ecb_oracle.encrypt(b"A" * AES_BS_B * 4, b"")  # 4 AES blocks
    blocks = [test_ecb[i : i + AES_BS_B] for i in range(0, len(test_ecb), AES_BS_B)]
    repeater = set()
    for block in blocks:
        repeater.add(bytes(block))
    if len(repeater) == len(blocks):
        raise InvalidECBMode
    else:
        print("ECB found")

    # Attack ciphertext with one byte short version and match
    plaintext = bytearray()
    counter = 1
    while counter < len(unknown):
        # Form dictionary of possible output blocks
        dict_options = {}
        block_num = math.floor(counter / blocksize)

        dict_crafted = bytearray(
            b"A" * (blocksize * (block_num + 1) - counter) + plaintext
        )
        input_crafted = bytearray(b"A" * (blocksize * (block_num + 1) - counter))

        # Try each possible byte till find the match
        for letter in range(0, 255):
            crafted_var = dict_crafted + bytes([letter])
            oracle_result = ecb_oracle.encrypt(crafted_var, unknown)
            dict_options[oracle_result[: blocksize * (block_num + 1)]] = crafted_var

        oracle_result = ecb_oracle.encrypt(input_crafted, unknown)
        check_blocks = oracle_result[: (block_num + 1) * blocksize]
        matched_block = dict_options[check_blocks]
        plaintext.append(matched_block[-1])
        counter += 1

    ch12 = plaintext
    print(f"{ch12=}")


if __name__ == "__main__":
    print("CHALLENGE 9")
    challenge_9()
    print("\nCHALLENGE 10")
    challenge_10()
    print("\nCHALLENGE 11")
    challenge_11()
    print("\nCHALLENGE 12")
    challenge_12()
