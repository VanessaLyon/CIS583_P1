from web3 import Web3
import eth_account
import os

# Enable the unaudited HDWallet features
eth_account.Account.enable_unaudited_hdwallet_features()

def get_keys(challenge, keyId=0, filename="eth_mnemonic.txt"):
    """
    Generate a stable private key and sign a message.
    challenge - byte string
    keyId (integer) - which key to use
    filename - filename to read and store mnemonics
    """

    w3 = Web3()

    # Check if we have enough mnemonics in the file
    try:
        with open(filename, 'r') as file:
            mnemonics = file.readlines()
    except FileNotFoundError:
        mnemonics = []

    # If we need more mnemonics, generate and save them
    if keyId >= len(mnemonics):
        # Create a new mnemonic
        new_mnemonic = eth_account.Account.create().address
        mnemonics.append(new_mnemonic + '\n')
        with open(filename, 'w') as file:
            file.writelines(mnemonics)

    # Retrieve the mnemonic for the requested keyId
    mnemonic = mnemonics[keyId].strip()

    # Create account from mnemonic
    acct = w3.eth.account.from_mnemonic(mnemonic)

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
