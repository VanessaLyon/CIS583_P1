from web3 import Web3
import eth_account
import os
import random


def generate_mock_mnemonic(num_words=12):
    """Generate a mock mnemonic phrase with num_words words, with improved randomness."""
    word_list = [
        "apple", "banana", "cherry", "date", "elderberry", "fig", "grape", 
        "honeydew", "kiwi", "lemon", "mango", "nectarine", "orange", "papaya", 
        "quince", "raspberry", "strawberry", "tangerine", "grapefruit", 
        "blueberry", "melon", "coconut", "apricot", "pear", "peach", "plum", 
        "lychee", "lime", "jackfruit", "guava", "pomegranate", "pineapple"
    ]

    # Shuffle the word list to increase randomness
    random.shuffle(word_list)

    # Select the first num_words words from the shuffled list
    return ' '.join(word_list[:num_words])

def get_keys(challenge, keyId=0, filename="eth_mnemonic.txt"):
    """
    Generate a stable private key using mock mnemonics and sign a message.
    challenge - byte string
    keyId (integer) - which key to use
    filename - filename to read and store mock mnemonics
    """

    w3 = Web3()

    # Check if we have enough mock mnemonics in the file
    try:
        with open(filename, 'r') as file:
            mock_mnemonics = file.readlines()
    except FileNotFoundError:
        mock_mnemonics = []

    # If we need more mock mnemonics, generate and save them
    if keyId >= len(mock_mnemonics):
        new_mnemonic = generate_mock_mnemonic()
        mock_mnemonics.append(new_mnemonic + '\n')
        with open(filename, 'w') as file:
            file.writelines(mock_mnemonics)

    # Retrieve the mock mnemonic for the requested keyId
    mnemonic = mock_mnemonics[keyId].strip()

    # Create a new Ethereum account for each mock mnemonic
    acct = eth_account.Account.create(mnemonic)
    
    # Sign the challenge
    msg = eth_account.messages.encode_defunct(challenge)
    sig = acct.sign_message(msg)

    eth_addr = acct.address
    assert eth_account.Account.recover_message(msg, signature=sig.signature.hex()) == eth_addr, "Failed to sign message properly"

    return sig, eth_addr

if __name__ == "__main__":
    for i in range(4):
        challenge = os.urandom(64)
        sig, addr = get_keys(challenge=challenge, keyId=i)
        print(addr)
