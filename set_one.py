import crypt

"""
Set 1 of Cryptopals
https://cryptopals.com/sets/1
"""


def challenge_1() -> None:
    """Convert hex to base64
    https://cryptopals.com/sets/1/challenges/1"""

    ch1 = crypt.hex_to_base64(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    )
    print(f"{ch1=}")


def challenge_2() -> None:
    """Fixed XOR
    https://cryptopals.com/sets/1/challenges/2"""

    msg_bytes1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    msg_bytes2 = bytes.fromhex("686974207468652062756c6c277320657965")
    ch2 = crypt.fixed_xor(msg_bytes1, msg_bytes2)
    print(f"{ch2=}")


if __name__ == "__main__":
    print("CHALLENGE 1")
    challenge_1()
    print("\nCHALLENGE 2")
    challenge_2()
