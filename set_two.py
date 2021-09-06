import math
import crypt
import random
from typing import Union
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
        dict_options: dict[bytes, bytearray] = {}
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


def challenge_13() -> None:
    """ECB cut-and-paste
    https://cryptopals.com/sets/2/challenges/13"""

    def encoded_profile_parse(profile: str) -> dict[str, str]:
        separated = profile.split("&")
        dict_output = {}
        for item in separated:
            item_parts = item.split("=")
            dict_output[item_parts[0]] = item_parts[1]
        return dict_output

    def profile_create(email: str, uid: int) -> dict[str, Union[str, int]]:
        uid += 1
        email = email.replace("&", "")
        email = email.replace("=", "")
        return {"email": email, "uid": uid, "role": "user"}

    def profile_encode(profile: dict[str, Union[str, int]]) -> str:
        encoded = ""
        for i, v in profile.items():
            encoded = encoded + f"{i}={v}&"
        return encoded[:-1]

    # Oracle functions
    class CutPasteOracle:
        def __init__(self):
            self.key = crypt.rand_key()

        def encrypt(self, encoded_profile: str) -> bytes:
            return crypt.aes_ecb_encrypt(bytes(encoded_profile, "utf-8"), self.key)

        def decrypt(self, encrypted_profile: bytes) -> dict[str, str]:
            decrypted = crypt.aes_ecb_decrypt(encrypted_profile, self.key)
            print(decrypted)
            return encoded_profile_parse(str(decrypted))

    # Attacker has access to the oracle functions but not the key.
    # Figure out input that puts the text "user" in last block alone:
    # Cannot put "role=user" in last block as cannot crafted input that
    # contains and equals sign.
    # Input email bob@cattle.far causes 32 bytes before "user". This is
    # exactly two blocks, thus final block is "user" is 4 bytes with 12
    # bytes of padding.
    uid = 0
    cut_paste_oracle = CutPasteOracle()
    profile = profile_create("bob@cattle.far", uid)
    encoded_profile = profile_encode(profile)
    encrypted_profile = cut_paste_oracle.encrypt(encoded_profile)

    # Generate ciphertexts of a block containing "admin" and padding:
    # "email="" is 6 bytes, thus we need 10 bytes of irrelevant padding
    # then "admin" and 11 bytes of proper pkcs7 padding.
    crafted_input = "A" * 10 + "admin" + "\x0b" * 11
    crafted_profile = profile_create(crafted_input, uid)
    crafted_encoded = profile_encode(crafted_profile)
    crafted_cipher = cut_paste_oracle.encrypt(crafted_encoded)
    sub_block = crafted_cipher[AES_BS_B : AES_BS_B * 2]

    # Replace final block of encrypted_profile with the crafted sub_block.
    encrypted_profile = encrypted_profile[:-AES_BS_B] + sub_block

    # Decrypt to view admin has been set
    decrypted_profile = cut_paste_oracle.decrypt(encrypted_profile)
    print(f"ch13={decrypted_profile}")


if __name__ == "__main__":
    print("CHALLENGE 9")
    challenge_9()
    print("\nCHALLENGE 10")
    challenge_10()
    print("\nCHALLENGE 11")
    challenge_11()
    print("\nCHALLENGE 12")
    challenge_12()
    print("\nCHALLENGE 13")
    challenge_13()
