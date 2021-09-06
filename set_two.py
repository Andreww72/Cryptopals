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


if __name__ == "__main__":
    print("CHALLENGE 9")
    challenge_9()
    print("\nCHALLENGE 10")
    challenge_10()
    print("\nCHALLENGE 11")
    challenge_11()
