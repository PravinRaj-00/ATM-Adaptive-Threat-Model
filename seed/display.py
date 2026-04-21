import os
import platform


def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def display_mnemonic(mnemonic: str):
    """
    Securely display the mnemonic phrase to the user
    in a 12x2 ASCII table layout.
    """

    print("\n[MNEMONIC — WRITE THIS DOWN SECURELY]\n")

    words = mnemonic.split()

    if len(words) != 24:
        print("Warning: unexpected mnemonic length.")

    left = words[:12]
    right = words[12:]

    border = "+----+-------------+----+-------------+"

    print(border)

    for i in range(12):

        left_index = i + 1
        right_index = i + 13

        left_word = left[i]
        right_word = right[i] if i < len(right) else ""

        print(
            f"| {left_index:02d} | {left_word:<11} | {right_index:02d} | {right_word:<11} |"
        )

    print(border)

    print("\nWrite these words IN ORDER on paper.")
    print("Do NOT photograph this seed phrase.")
    print("Store the backup offline and securely.\n")