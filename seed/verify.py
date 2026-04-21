import random

class MnemonicVerificationError(Exception):
    pass

def verify_user_recorded_mnemonic(mnemonic: str, challenges: int = 3):
    """
    Challenge user with random mnemonic word checks.

    Parameters
    ----------
    mnemonic : str
    challenges : int
        Number of random words to verify.
    """

    words = mnemonic.split()
    total_words = len(words)

    print("\n[Mnemonic Verification]")
    print("----------------------------------------")
    print("Confirm you recorded the seed correctly.")
    print(f"You will be asked for {challenges} random words.")
    print("----------------------------------------")

    indices = random.sample(range(total_words), challenges)

    for idx in indices:

        expected = words[idx]

        user = input(f"Enter word #{idx + 1}: ").strip().lower()

        if user != expected:
            raise MnemonicVerificationError(
                f"Verification failed at word #{idx + 1}."
            )

    print("\n[Verification successful]")
    print("Mnemonic verified correctly.\n")
    print("Proceeding to secure lifecycle.\n")

    return True