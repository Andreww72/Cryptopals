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


if __name__ == "__main__":
    print("CHALLENGE 1")
    challenge_1()
