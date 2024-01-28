from web3 import Web3
import eth_account
import os

def get_mnemonic(account):
    """Retrieve the mnemonic for an Ethereum account."""
    try:
        mnemonic = account.from_key(account.key).mnemonic
        return mnemonic
    except ValueError:
        print("Account does not have a valid mnemonic.")
        return None

def store_mnemonic(mnemonic, filename="eth_mnemonic.txt"):
    """Store the mnemonic in a file."""
    with open(filename, 'a') as file:
        file.write(mnemonic + '\n')

def get_keys(challenge, keyId=0, filename="eth_mnemonic.txt"):
    """
    Generate a stable private key and sign a message.
    challenge - byte string
    keyId (integer) - which key to use
    filename - filename to read and store mnemonics
    """

    w3 = Web3()

    # Enable unaudited HD wallet features
    Account.enable_unaudited_hdwallet_features()

    # Check if we have enough mnemonics in the file
    try:
        with open(filename, 'r') as file:
            mnemonics = file.readlines()
    except FileNotFoundError:
        mnemonics = []

    # If we need more mnemonic, generate and save them
    if keyId >= len(mnemonics):
        acct = eth_account.Account.create()
        my_mnem = get_mnemonic(acct)
        mnemonics.append(my_mnem + '\n')
        with open(filename, 'w') as file:
            file.writelines(mnemonics)
    else:
        # Use existing mnemonic to recreate the account
        my_mnem = mnemonics[keyId].strip()
        acct = eth_account.Account.from_mnemonic(my_mnem)

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
