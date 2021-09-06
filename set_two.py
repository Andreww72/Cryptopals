import crypt
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


if __name__ == "__main__":
    print("CHALLENGE 9")
    challenge_9()
    print("\nCHALLENGE 10")
    challenge_10()
