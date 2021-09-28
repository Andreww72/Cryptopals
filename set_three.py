#!/bin/python3
from base64 import b64decode
import random
import crypt
import math


AES_BS_B = crypt.AES_BS_B

"""
Set 3 of Cryptopals
https://cryptopals.com/sets/3
"""


def challenge_17() -> None:
    """CBC padding oracle
    https://cryptopals.com/sets/3/challenges/17"""

    # Create padding oracle
    class CBCPaddingOracle:
        def __init__(self):
            self.key = crypt.rand_key(AES_BS_B)

        def encrypt(self, plaintext: str):
            iv = crypt.rand_key(AES_BS_B)
            return crypt.aes_cbc_encrypt(plaintext, self.key, iv), iv

        def decrypt(self, ciphertext: bytes, iv: bytes):
            try:
                decrypted = crypt.aes_cbc_decrypt(ciphertext, self.key, iv)
            # Check padding
            except (crypt.PaddingLengthError, crypt.PaddingValueError):
                return False
            return True

    # Setup data and oracle
    padding_oracle = CBCPaddingOracle()
    with open("data/set3_ch17_data.txt", "r") as file_ch17:
        data_ch17 = file_ch17.readlines()
        plaintext = b64decode(data_ch17[random.randint(0, 9)].strip())

    # Attacker gets IV (implementing by reuse in decryption)
    print(plaintext)
    ciphertext, iv = padding_oracle.encrypt(plaintext)
    options = range(0, 255)

    # C1, C2
    # Change last block of C1 and send (IV, C or F, C2) to oracle
    # If padding correct, know last byte of D(C2) XOR C1' is 0x01.
    # Thus M = D(C2) = C1' XOR 0x01. Else keep changing C1' guess.
    # If target block contains padding bytes, additional attempt required.

    def padded_oracle_decrypt_block(block1: bytes, block2: bytes) -> bytes:
        """
        Use padded oracle attack on given blocks

        :param block1: block that is cbc bit flipped
        :param block2: block that is decrypted
        :returns: decrypted block2
        """

        # Variables
        # c: ciphertext block1
        # f: forged cipthertext block1
        # x: intermediary calc
        # m: plaintext block2

        def crack_byte(expected_padding, f, c, intermediaries, decrypted_block):
            x = crypt.fixed_xor(expected_padding, bytes([f]))
            m = crypt.fixed_xor(x, bytes([c]))
            decrypted_block.append(m)
            intermediaries.append(x)

        decrypted_block: list[bytes] = []
        intermediaries: list[bytes] = []

        # Setup block size
        assert len(block1) == len(block2)
        block_size = len(block1)
        block1 = bytearray(block1)

        # Crack each byte in reverse order
        for i in range(block_size):
            target_pos = block_size - i - 1
            c = block1[target_pos]
            expected_padding = bytes([i + 1])
 
            # Prepare bytes already found
            for j in range(i):
                fx = crypt.fixed_xor(expected_padding, intermediaries[j])
                block1[block_size-j-1] = int.from_bytes(fx, "big")

            # Try all 255 possible bytes until successful padding found
            found = False
            f_is_c_case = None
            for f in options:
                block1[target_pos] = f

                # Test padding at oracle
                if padding_oracle.decrypt(block2, block1):

                    # This non-found case goes off when in the last block only
                    # And only in the real text part of the last block
                    if f == c:
                        f_is_c_case = int(f)
                        continue

                    found = True

                    # Crack byte now a padding success is returned
                    crack_byte(expected_padding, f, c, intermediaries, decrypted_block)
                    break
            
            if not found:
                # Crack byte in this last block weird case
                crack_byte(expected_padding, f_is_c_case, c, intermediaries, decrypted_block)

        decrypted_block.reverse()
        return decrypted_block

    solution = []
    iv_cipher = bytearray(iv + ciphertext)

    # Solve each block (requires it's previous)
    for block in range(len(iv_cipher) // AES_BS_B - 1):
        solution.append(
            padded_oracle_decrypt_block(
                iv_cipher[block*AES_BS_B:(block+1)*AES_BS_B],
                iv_cipher[(block+1)*AES_BS_B:(block+2)*AES_BS_B]
            )
        )
        ch17 = ""
    
    ch17 = b""
    for solved_block in solution:
        ch17 = ch17 + b"".join(solved_block)
    ch17 = crypt.pkcs7_unpad(ch17)
    print(f"{ch17=}")


if __name__ == "__main__":
    print("CHALLENGE 17")
    challenge_17()
