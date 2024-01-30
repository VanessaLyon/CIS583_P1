length of file is 4 
using existing mnemonic 
Address: 0x727A8a73171CD7a3c726b7D3119A0161c530E12d 
Recovered address: 0x727A8a73171CD7a3c726b7D3119A0161c530E12d 
Message Hash: 0xf7b8ecc83c6b63bf1901f07e26366d56d52aedd05eb8115a2429b48b47fa7a53 
r: 94343010483293998759083952316790203511358027261856158422595159174534341612511 
s: 33671077074897696828017966532566077962807409629136516827823243677209339009534 
v: 28 
Signature: 0xd094406b970b88ddd23d7b7f35bfca16c16f7cf68bc2e9d4f7c2ae32afe453df4a71277ddd6408efc878adf457e7a1aa251dab666eeeead1e12e7033d3de99fe1c 
Failure: signature failed to verify 
Signature: SignedMessage(messageHash=HexBytes('0xf7b8ecc83c6b63bf1901f07e26366d56d52aedd05eb8115a2429b48b47fa7a53'), 
r=94343010483293998759083952316790203511358027261856158422595159174534341612511, 
s=33671077074897696828017966532566077962807409629136516827823243677209339009534, 
v=28, 
signature=HexBytes('0xd094406b970b88ddd23d7b7f35bfca16c16f7cf68bc2e9d4f7c2ae32afe453df4a71277ddd6408efc878adf457e7a1aa251dab666eeeead1e12e7033d3de99fe1c')) 
Address: 0x727A8a73171CD7a3c726b7D3119A0161c530E12d 
Success: 0x727A8a73171CD7a3c726b7D3119A0161c530E12d has 300000000000000000 Wei 
length of file is 4 
using existing mnemonic 
Address: 0x727A8a73171CD7a3c726b7D3119A0161c530E12d 
Recovered address: 0x727A8a73171CD7a3c726b7D3119A0161c530E12d 
Message Hash: 0x825596debfe8c86b45e654902c7d7e4ecc9a2a6528fa5f0887c718ad96386369 
r: 22382096915052087739763943303156230044256788105165929889667624738206501877227 
s: 20363307977238965145808751787788342904190072720903088965091443749559029371431 
v: 27 
Signature: 0x317bd1636d09db0a4bc6429262914b57bbf49040338b425370ab65c10054b5eb2d05394ff9a4be37b8f2a33cf93e8c675dbe717b2d4b4918851ea0a5d4da92271b 
Failure: signature failed to verify 
Signature: SignedMessage(messageHash=HexBytes('0x825596debfe8c86b45e654902c7d7e4ecc9a2a6528fa5f0887c718ad96386369'), 
r=22382096915052087739763943303156230044256788105165929889667624738206501877227, 
s=20363307977238965145808751787788342904190072720903088965091443749559029371431, 
v=27, 
signature=HexBytes('0x317bd1636d09db0a4bc6429262914b57bbf49040338b425370ab65c10054b5eb2d05394ff9a4be37b8f2a33cf93e8c675dbe717b2d4b4918851ea0a5d4da92271b')) 
Address: 0x727A8a73171CD7a3c726b7D3119A0161c530E12d 
Success: 0x727A8a73171CD7a3c726b7D3119A0161c530E12d has 1000000000000000000 Wei 
Run Tests Score : 50.0

At this point, I am returning sig = Account.sign_message(encoded_message, private_key), but maybe I should return another format.

from web3 import Web3, Account
from eth_account.messages import encode_defunct
import os

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
    encoded_message = encode_defunct(text=challenge)
    sig = Account.sign_message(encoded_message, private_key)

    recovered_addr = Account.recover_message(encoded_message, signature=sig.signature) 
    
    # Debugging prints
    print(f"Address: {eth_addr}")
    print(f"Recovered address: {recovered_addr}")
    print(f"Message Hash: {sig.messageHash.hex()}")
    print(f"r: {sig.r}")
    print(f"s: {sig.s}")
    print(f"v: {sig.v}")
    print(f"Signature: {sig.signature.hex()}")

    assert Account.recover_message(encoded_message, signature=sig.signature) == eth_addr, "Failed to sign message properly"

    return sig, eth_addr

if __name__ == "__main__":
    for i in range(4):
        challenge = os.urandom(64)
        sig, addr = get_keys(challenge=challenge, keyId=i)
        print(addr)
