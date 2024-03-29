from web3 import Web3, Account
from eth_account.messages import encode_defunct
from eth_utils.curried import to_hex, to_bytes
import os
import base64

def get_keys(challenge, keyId, filename="eth_mnemonic.txt"):
    """
    Generate a stable private key using a mnemonic, and sign a message.
    challenge - byte string
    keyId (integer) - which key to use
    filename - filename to read and store mnemonics
    """

    w3 = Web3()
    Account.enable_unaudited_hdwallet_features()

    # Check if we have enough mnemonics in the file
    mnemonics = []
    try:
        with open(filename, 'r') as file:
            mnemonics = file.readlines()
    except FileNotFoundError:
        mnemonics = []

    print('length of file is ', len(mnemonics))

    # If we need more mnemonics, generate and save them
    if keyId >= len(mnemonics):
        account, mnemonic_phrase = Account.create_with_mnemonic()
        print('phrase: ', mnemonic_phrase)
        mnemonics.append(mnemonic_phrase + '\n')
        with open(filename, 'w') as file:
            file.writelines(mnemonics)
    else:
        print('using existing mnemonic')
        mnemonic_phrase = mnemonics[keyId].strip()
        account = Account.from_mnemonic(mnemonic_phrase)

    private_key = account.key
    eth_addr = account.address

    # Sign the challenge
    #encoded_message = encode_defunct(text=challenge.hex())
    #challenge_converted =  base64.b64encode(challenge).decode('utf-8')
    #print(challenge)
    #print(challenge_converted)
        
    encoded_message = encode_defunct(challenge)
    sig = Account.sign_message(encoded_message, private_key)

    recovered_addr = Account.recover_message(encoded_message, signature=sig.signature) 
    
    # Debugging prints
    #print(f"Address: {eth_addr}")
    #print(f"Recovered address: {recovered_addr}")
    #print(f"Message Hash: {sig.messageHash.hex()}")
    #print(f"r: {sig.r}")
    #print(f"s: {sig.s}")
    #print(f"v: {sig.v}")
    #print(f"Signature: {sig.signature.hex()}")

    Account.recover_message(encoded_message, signature=sig.signature)
    assert Account.recover_message(encoded_message, signature=sig.signature) == eth_addr, "Failed to sign message properly"

    return sig, eth_addr

if __name__ == "__main__":
    for i in range(4):
        challenge = os.urandom(64)
        sig, addr = get_keys(challenge=challenge, keyId=i)
        print(addr)
