import math
import crypt
import random
import secrets
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


def challenge_14() -> None:
    """Byte-at-a-time ECB decryption (Harder)
    https://cryptopals.com/sets/2/challenges/14"""

    # Take oracle from challenge 12 and repeat but with random prefix
    class ECB_Oracle_Harder:
        def __init__(self):
            self.key = crypt.rand_key()
            self.prefix = secrets.token_bytes(random.randint(0, 255))
            print(f"{len(self.prefix)=}")

        def encrypt(self, append_known: bytes, ciphertext: bytes):
            return crypt.aes_ecb_encrypt(
                self.prefix + append_known + ciphertext, self.key
            )

    data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    unknown = b64decode(data)
    ecb_oracle = ECB_Oracle_Harder()
    blocksize = AES_BS_B

    # Attack length of prefix for use in following byte by byte attack
    # Reduce prefix_solver by one until three identical CT A blocks
    # becomes two, then calculate # As in the last prefix block and
    # thus know length of the prefix.
    counter = 0
    while True:
        num_As = blocksize * 4 - counter
        prefix_solver = bytearray(b"A" * num_As)
        oracle_result = ecb_oracle.encrypt(prefix_solver, unknown)
        block_count = len(oracle_result) // blocksize

        blocks: list[bytes] = []
        for i in range(block_count):
            blocks.append(oracle_result[blocksize * i : blocksize * (i + 1)])

        if len(blocks) - len(set(blocks)) == 1:
            # Find index of duplicate input CTs
            for i in range(block_count):
                if (
                    oracle_result[blocksize * i : blocksize * (i + 1)]
                    == oracle_result[blocksize * (i + 1) : blocksize * (i + 2)]
                ):
                    blocks_before_crafted = i

            # Calculate prefix length
            prefix_len = blocks_before_crafted * blocksize - (
                num_As - (blocksize * 3 - 1)
            )
            print(f"{prefix_len=}")
            break
        counter += 1

    # Attack ciphertext with one byte short version and match
    plaintext = bytearray()
    counter = 1
    prefix_pad_len = blocksize - prefix_len % blocksize  # blocksize-remainder
    prefix_total = prefix_len + prefix_pad_len

    while counter < len(unknown):
        # Form dictionary of possible output blocks
        dict_options: dict[bytes, bytearray] = {}
        block_num = math.floor(counter / blocksize)

        # Versions with and without prefix padded for both input and storing
        dict_crafted = bytearray(
            b"P" * prefix_pad_len
            + b"A" * (blocksize * (block_num + 1) - counter)
            + plaintext
        )
        input_crafted = bytearray(
            b"P" * prefix_pad_len + b"A" * (blocksize * (block_num + 1) - counter)
        )

        for letter in range(0, 255):
            dict_crafted_input = dict_crafted + bytes([letter])
            oracle_result = ecb_oracle.encrypt(dict_crafted_input, unknown)
            dict_options[
                oracle_result[: prefix_total + blocksize * (block_num + 1)]
            ] = dict_crafted_input

        oracle_result = ecb_oracle.encrypt(input_crafted, unknown)
        check_blocks = oracle_result[: prefix_total + blocksize * (block_num + 1)]
        matched_block = dict_options[check_blocks]
        plaintext.append(matched_block[-1])
        counter += 1

    ch14 = plaintext
    print(f"{ch14=}")


def challenge_15() -> None:
    """PKCS#7 padding validation
    https://cryptopals.com/sets/2/challenges/15"""

    def pkcs7_validate(plaintext: bytes, blocksize: int = AES_BS_B) -> bool:
        """Validate pkcs#7 padding on a plaintext message"""

        if not len(plaintext) % blocksize == 0:
            raise crypt.PaddingLengthError

        last_value = plaintext[-1]
        last_value_int = int(last_value)
        check_count = 0
        for char in reversed(plaintext):
            if char == last_value:
                check_count += 1
            else:
                break

        if not check_count == last_value_int:
            raise crypt.PaddingValueError

        return True

    # Test validation function on valid and invalid padding
    input1 = b"ICE ICE BABY\x04\x04\x04\x04"
    input2 = b"ICE ICE BABY\x05\x05\x05\x05"
    input3 = b"ICE ICE BABY\x01\x02\x03\x04"

    print(pkcs7_validate(input1))
    try:
        print(pkcs7_validate(input2))
    except (crypt.PaddingLengthError, crypt.PaddingValueError):
        print("Correctly caught padding validation failure")
    try:
        print(pkcs7_validate(input3))
    except (crypt.PaddingLengthError, crypt.PaddingValueError):
        print("Correctly caught padding validation failure")


def challenge_16() -> None:
    """CBC bitflipping attacks
    https://cryptopals.com/sets/2/challenges/16"""

    class CBCBitflipperOracle:
        def __init__(self):
            self.key = crypt.rand_key()
            self.iv = crypt.rand_key()

        def cbc_surround_encrypt(self, plaintext: str) -> bytes:
            prepend = "comment1=cooking%20MCs;userdata="
            append = ";comment2=%20like%20a%20pound%20of%20bacon"
            plaintext.replace(";", "")
            plaintext.replace("=", "")
            full_str = bytes(prepend + plaintext + append, "utf-8")
            return crypt.aes_cbc_encrypt(full_str, self.key, self.iv)

        def cbc_surround_decrypt(self, ciphertext: bytes) -> bool:
            decrypted = crypt.aes_cbc_decrypt(ciphertext, self.key, self.iv)
            print(decrypted)
            return b";admin=true" in decrypted

    oracle = CBCBitflipperOracle()

    # Find length of prepend and append:
    # Input text to pad prepend to blocksize and add another extra input
    # text to create two blocks of user data. The first is edited to
    # bitflip attack the second. Remaining append can be garbage.
    prepend_len = len("comment1=cooking%20MCs;userdata=")
    append_len = len(";comment2=%20like%20a%20pound%20of%20bacon")
    append_pad = AES_BS_B - append_len % AES_BS_B
    # Prepend is already a blocklength multiple so no pad

    crafted_input = "A" * (append_pad + AES_BS_B * 2)
    print(f"{len(crafted_input)}: {crafted_input}")
    ciphertext = bytearray(oracle.cbc_surround_encrypt(crafted_input))

    # CBC bitflip attack user data area to change the prepend
    # Target output includes ;admin=true; (12 len)
    # Edit third block to produce target output in fourth block
    target = b";admin=true;"
    replacement_block = bytearray()
    for i, target_byte in enumerate(target):
        edit_byte = ciphertext[2 * AES_BS_B + i]
        affect_byte = 65  # 'A' which was input
        mask = crypt.fixed_xor(bytes([affect_byte]), bytes([target_byte]))
        replace_byte = crypt.fixed_xor(bytes([edit_byte]), mask)
        replacement_block.append(int(replace_byte[0]))
    print(replacement_block)

    ciphertext[2 * AES_BS_B : 2 * AES_BS_B + len(target)] = replacement_block
    print(oracle.cbc_surround_decrypt(ciphertext))


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
    print("\nCHALLENGE 14")
    challenge_14()
    print("\nCHALLENGE 15")
    challenge_15()
    print("\nCHALLENGE 16")
    challenge_16()
