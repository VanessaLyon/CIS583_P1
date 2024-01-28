from web3 import Web3
import os
import binascii
import mnemonic
from mnemonic import Mnemonic
import random
import string


def generate_random_mnemonic():
    """Generate a random 12-word mnemonic phrase."""
    word_list = [
        "apple", "banana", "cherry", "date", "elderberry", "fig", "grape", 
        "honeydew", "kiwi", "lemon", "mango", "nectarine", "orange", "papaya", 
        "quince", "raspberry", "strawberry", "tangerine", "grapefruit", 
        "blueberry", "melon", "coconut", "apricot", "pear", "peach", "plum", 
        "lychee", "lime", "jackfruit", "guava", "pomegranate", "pineapple"
    ]

    # Shuffle and select 12 words from the word list
    selected_words = random.sample(word_list, 12)

    # Join the selected words to create the mnemonic phrase
    mnemonic_phrase = ' '.join(selected_words)

    return mnemonic_phrase

def get_keys(challenge, keyId, filename="eth_mnemonic.txt"):
    """
    Generate a stable private key, convert it to a mnemonic, and sign a message.
    challenge - byte string
    keyId (integer) - which key to use
    filename - filename to read and store mnemonics
    """

    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()

    # Check if we have enough mnemonics in the file
    mnemonics = []
    try:
        with open(filename, 'r') as file:
            mnemonics = file.readlines()
    except FileNotFoundError:
        mnemonics = []

    print('lenght of file is ', len(mnemonics))

    # If we need more mnemonics, generate and save them
    if keyId >= len(mnemonics):
        mnemonic_phrase = generate_random_mnemonic()
        print('phrase: ', mnemonic_phrase)
        mnemonics.append(mnemonic_phrase + '\n')
        with open(filename, 'w') as file:
            file.writelines(mnemonics)
    else:
        print('we are in the else')
        # Use an existing mnemonic to recreate the private key
        mnemonic_phrase = mnemonics[keyId].strip()

    # Derive the Ethereum address from the mnemonic phrase
    private_key = w3.eth.account.from_mnemonic(mnemonic_phrase).privateKey
    eth_addr = w3.eth.account.privateKeyToAccount(private_key).address

    # Sign the challenge
    msg = w3.eth.account.encode_defunct(challenge)
    sig = w3.eth.account.signHash(msg, private_key=private_key)

    assert w3.eth.account.recoverHash(msg, signature=sig.signature.hex()) == eth_addr, "Failed to sign message properly"

    return sig, eth_addr

if __name__ == "__main__":
    for i in range(4):
        challenge = os.urandom(64)
        sig, addr = get_keys(challenge=challenge, keyId=i)
        print(addr)
