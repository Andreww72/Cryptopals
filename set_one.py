from base64 import b64decode, b64encode
import crypt

"""
Set 1 of Cryptopals
https://cryptopals.com/sets/1
"""

LETTERS = range(0, 128)


def challenge_1() -> None:
    """Convert hex to base64
    https://cryptopals.com/sets/1/challenges/1"""

    ch1: str = crypt.hex_to_base64(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    )
    print(f"{ch1=}")


def challenge_2() -> None:
    """Fixed XOR
    https://cryptopals.com/sets/1/challenges/2"""

    msg_bytes1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    msg_bytes2 = bytes.fromhex("686974207468652062756c6c277320657965")
    ch2: bytes = crypt.fixed_xor(msg_bytes1, msg_bytes2)
    print(f"{ch2=}")


def challenge_3() -> None:
    """Single-byte XOR cipher
    https://cryptopals.com/sets/1/challenges/3"""

    scores: dict[int, float] = {}
    msgs: dict[int, str] = {}

    msg_bytes = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    for letter in LETTERS:
        res, score = crypt.single_xor_cipher(msg_bytes, letter)
        msgs[letter] = str(res, "utf-8")
        scores[letter] = score

    ordered_scores: dict[int, float] = dict(
        sorted(scores.items(), key=lambda x: x[1], reverse=True)
    )
    ch3 = list(ordered_scores)[0]
    print(f"{ch3=}: {round(scores[ch3], 2)}, {msgs[ch3]}")


def challenge_4() -> None:
    """Detect single-character XOR
    https://cryptopals.com/sets/1/challenges/4"""

    scores: dict[str, float] = {}
    msgs: dict[str, str] = {}

    with open("data/set1_ch4_data.txt", "r") as file_ch4:
        for i, line in enumerate(file_ch4):
            line = line.strip("\n")

            for letter in LETTERS:
                bytes_msg = bytes.fromhex(line)
                try:
                    res, score = crypt.single_xor_cipher(bytes_msg, letter)
                except UnicodeDecodeError:
                    continue

                msgs[f"{i}_{letter}"] = str(res, "utf-8").strip()
                scores[f"{i}_{letter}"] = score

    ordered_scores: dict[str, float] = dict(
        sorted(scores.items(), key=lambda x: x[1], reverse=True)
    )
    ch4 = list(ordered_scores)[0]

    print(f"{ch4=}: {round(scores[ch4], 2)}, {msgs[ch4]}")


def challenge_5() -> None:
    """Implement repeating-key XOR
    https://cryptopals.com/sets/1/challenges/5"""

    msg = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    ch5: str = crypt.repeating_key_xor(bytes(msg, "utf-8"), key).hex()
    print(f"{ch5=}")


def challenge_6() -> None:
    """Break repeating-key XOR
    https://cryptopals.com/sets/1/challenges/5"""

    dists: dict[int, float] = {}
    with open("data/set1_ch6_data.txt", "r") as file_ch6:
        bytes_data_ch6 = b64decode(file_ch6.read())

    # Find the keysize (smallest normalised edit dist)
    for keysize in range(2, 41):
        dist_list: list[float] = []
        key_chunks: list[bytes] = [
            bytes_data_ch6[i : i + keysize]
            for i in range(0, len(bytes_data_ch6), keysize)
        ]

        while True:
            try:
                k1 = key_chunks[0]
                k2 = key_chunks[1]
                dist = crypt.hamming_distance(k1, k2)
                dist_list.append(dist / keysize)
                del key_chunks[0]
                del key_chunks[1]
            except IndexError:
                break

        dist_avg = sum(dist_list) / len(dist_list)
        dists[keysize] = dist_avg

    ordered_sizes: dict[int, float] = dict(sorted(dists.items(), key=lambda x: x[1]))
    est_size = list(ordered_sizes)[0]
    print(f"Smallest normalised edit dist: {est_size}")

    # Break ciphertext in that keysize blocks
    blocks: list[bytes] = [
        bytes_data_ch6[i : i + est_size]
        for i in range(0, len(bytes_data_ch6), est_size)
    ]

    # Transpose blocks so number of blocks = size
    blocks_t: list[list[bytes]] = []
    for n in range(0, est_size):
        transpose: list[bytes] = []
        for block in blocks:
            try:
                transpose.append(block[n : n + 1])
            except IndexError:
                pass
        blocks_t.append(transpose)

    # Solve each block as a single char xor
    key: list[int] = []
    for bytes_block in blocks_t:
        scores = {}
        msgs = {}
        for letter in LETTERS:
            bytes_obj = b"".join(bytes_block)
            res, score = crypt.single_xor_cipher(bytes_obj, letter)
            msgs[letter] = str(res, "utf-8")
            scores[letter] = score

        ordered_scores: dict[int, float] = dict(
            sorted(scores.items(), key=lambda x: x[1], reverse=True)
        )
        solved_char = list(ordered_scores)[0]
        key.append(solved_char)

    solved_key = [chr(a) for a in key]
    print("ch6=" + "".join(solved_key))


if __name__ == "__main__":
    print("CHALLENGE 1")
    challenge_1()
    print("\nCHALLENGE 2")
    challenge_2()
    print("\nCHALLENGE 3")
    challenge_3()
    print("\nCHALLENGE 4")
    challenge_4()
    print("\nCHALLENGE 5")
    challenge_5()
    print("\nCHALLENGE 6")
    challenge_6()
