# https://kobl.one/blog/create-full-ethereum-keypair-and-address/
# https://medium.com/validitylabs/how-to-interact-with-the-ethereum-blockchain-and-create-a-database-with-python-and-sql-3dcbd579b3c0
# https://www.dappuniversity.com/articles/web3-py-intro
# https://medium.com/@ashiqgiga07/cryptography-with-python-hashing-d0b7dbf7767
# https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc.md
# https://en.bitcoin.it/wiki/Secp256k1
# https://www.secg.org/sec2-v2.pdf read also : https://crypto.stackexchange.com/questions/56438/secp521r1-elliptic-curve-base-point-coordinates
# Security : https://github.com/warner/python-ecdsa
# https://ethereum.stackexchange.com/questions/3542/how-are-ethereum-addresses-generated


# Packages :
# https://github.com/warner/python-ecdsa

# Create function to generate key
# Create system to store
# Create wallet to send/recieve

# import OpenSSL.crypto as crypto

# ec = crypto.get_elliptic_curve("secp256k1")
# key = crypto.PKey()

from tinyec.ec import SubGroup, Curve
from Crypto.Random.random import randint
from web3 import Web3

### Key and address generation

# Defining the elliptic curve

p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)  
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
h = 1

x = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
y = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
g = (x, y)

# We can check that the point is really on the curve using 
# print(y**2 % p == (x**3 + 7) % p) 

field = SubGroup(p, g, n, h)
curve = Curve(a = 0, b = 7, field = field, name = 'secp256k1')

# print('curve:', curve)

# Generating the private and the public keys
# Note that tinyec already posses a key generator but it is based on standard python random
# which is not secure

#private_key = randint(1, n)
#private_key = int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
# yields 0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9
private_key = int("208065a247edbe5df4d86fbdc0171303f23a76961be9f6013850dd2bdc759bbb", 16)
# yields 0x0BED7ABd61247635c1973eB38474A2516eD1D884
# see https://kobl.one/blog/create-full-ethereum-keypair-and-address/

public_key = private_key * curve.g

public_key_hex = Web3.toHex(public_key.x)[2:] + Web3.toHex(public_key.y)[2:]

# public_key = None

# Hashing to obtain the address
# https://github.com/ethereumbook/ethereumbook/blob/develop/04keys-addresses.asciidoc#ethereum-addresses
# https://ethereum.stackexchange.com/questions/6520/can-i-use-the-same-private-key-for-ethereum-and-bitcoin?rq=1

address = Web3.keccak(hexstr = public_key_hex).hex()
address = "0x" + address[-40:]

# Transform the address to have check sum

# Example ('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359' yields '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359'
# Here for some reason we need hash not of hex, but of Bytes
# address_hash = Web3.keccak(address.encode('utf-8')).hex()  
# then we need to loop 

# otherwise this works
address = Web3.toChecksumAddress(address)

#print(address)

# https://ethereum.stackexchange.com/questions/2045/is-ethereum-wallet-address-case-sensitive/2046#2046


### Storage of public key

# We need to generate a new symteric key
# We need to store the crypter private key, the hash of the pwd and the salt
# https://nitratine.net/blog/post/encryption-and-decryption-in-python/
# https://www.thepythoncode.com/article/encrypt-decrypt-files-symmetric-python
# https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/

# Maybe use the Crypto Random number generation for salt and private key generation

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import json

password = b"password"

salt = get_random_bytes(16)
#salt = b"saltsaltsaltsalt"

#password_hex = Web3.keccak(hexstr = password + salt).hex()
#key = password + salt

# Then we need key derivation function to get right size which is 16 bytes
# we choose a big N which takes 5 seconds, to stop bruteforce

key = scrypt(password, salt, 32, N = 2**20, r = 8, p = 1)

#salt = encode(salt, "SALT")

#salt = b64encode(salt).decode('utf-8')

# password = None

# Here convert and store salt
# There is no need to store hasshed password !

# Transform the data into bytes using utf-8
# the data has to be a multiple of 16 bytes in len

private_key = Web3.toHex(private_key)[2:] 
data = str(private_key).encode('utf-8')

cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))

salt = salt.hex()
iv = cipher.iv.hex()
ct = ct_bytes.hex()

output = {"salt" : salt, "initialization vector" : iv, "encrypted private key" : ct}

with open(address + '.txt', 'w') as json_file:
	json.dump(output, json_file)


### Decrypting the data 
with open(address + '.txt') as f:
	data = json.load(f)

salt = data['salt']
iv = data['initialization vector'] 
ct = data['encrypted private key']

salt = bytes.fromhex(salt)
iv = bytes.fromhex(iv)
ct = bytes.fromhex(ct)

key = scrypt(password, salt, 32, N = 2**20, r = 8, p = 1)

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), AES.block_size)
# print(pt.decode('utf-8'))


# Remake key

### Mathod using key derivation and computing each time

# Probably easier to use a key derivation function and to recompute public/private keys each time

# from Crypto.Protocol.KDF import scrypt

# password = b"password"

# salt = b""

# # Here we would need to check that the number generated is always smaller than n
# # since 2 ** 30 < n, we can probably use 30
# key = scrypt(password, salt, 30, N = 2**20, r = 8, p = 1)

# # This is probably a bad idea since we fix here that the length has to be 30, which is probably a weakness

# private_key = int.from_bytes(key, byteorder='big')




