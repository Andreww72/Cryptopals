import crypt

"""
Set 1 of Cryptopals
https://cryptopals.com/sets/1
"""

LETTERS = range(0, 128)


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


def challenge_3() -> None:
    """Single-byte XOR cipher
    https://cryptopals.com/sets/1/challenges/3"""

    scores = {}
    msgs = {}
    msg_bytes = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )

    for letter in LETTERS:
        res, score = crypt.single_xor_cipher(msg_bytes, letter)
        msgs[letter] = res
        scores[letter] = score

    ordered_scores: dict[int, float] = dict(
        sorted(scores.items(), key=lambda x: x[1], reverse=True)
    )
    ch3 = list(ordered_scores)[0]
    print(f"{ch3=}: {round(scores[ch3], 2)}, {str(msgs[ch3], 'utf-8')}")


def challenge_4() -> None:
    """Detect single-character XOR
    https://cryptopals.com/sets/1/challenges/4"""

    scores = {}
    msgs = {}

    with open("data/set1_ch4_data.txt", "r") as file_ch4:
        for i, line in enumerate(file_ch4):
            line = line.strip("\n")

            for letter in LETTERS:
                bytes_msg = bytes.fromhex(line)
                try:
                    res, score = crypt.single_xor_cipher(bytes_msg, letter)
                except UnicodeDecodeError:
                    continue

                msgs[f"{i}_{letter}"] = res
                scores[f"{i}_{letter}"] = score

    ordered_scores: dict[str, float] = dict(
        sorted(scores.items(), key=lambda x: x[1], reverse=True)
    )
    ch4 = list(ordered_scores)[0]

    print(f"{ch4=}: {round(scores[ch4], 2)}, {str(msgs[ch4], 'utf-8').strip()}")


if __name__ == "__main__":
    print("CHALLENGE 1")
    challenge_1()
    print("\nCHALLENGE 2")
    challenge_2()
    print("\nCHALLENGE 3")
    challenge_3()
    print("\nCHALLENGE 4")
    challenge_4()
