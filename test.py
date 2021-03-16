import os
import ecdsa
import hashlib
import base58
import binascii

# STATIC KEY USAGE
private_key_static = "29a59e66fe370e901174a1b8296d31998da5588c7e0dba860f11d65a3adf2736"
# PRINTOUT FROM STATIC PRIVATE KEY
print("This is my Private Key: " + private_key_static)

# NON STATIC PRIVATE KEY USAGE
#private_key = os.urandom(32).encode("hex")
# print "this is my private key: " + private_key

# 80-BYTE EXTENDED PRIVATE KEY
private_key_plus_80byte = (('80') + private_key_static)

# PRINTOUT 80-BYTE EXTENDED PRIVATE KEY
print("This is my 80 Byte Private Key: " + private_key_plus_80byte)

# PRIVATE! SIGNING KEY ECDSA.SECP256k1
sk = ecdsa.SigningKey.from_string(bytearray.fromhex(
    private_key_static), curve=ecdsa.SECP256k1)

# PUBLIC! VERIFYING KEY (64 BYTE LONG, MISSING 04 BYTE AT THE BEGINNING)
vk = sk.verifying_key

# PUBLIC KEY
public_key =  binascii.hexlify(b'\04'+vk.to_string())  # ('\04' + vk.to_string()).encode("hex")
# PRINTOUT PUBLIC KEY
print("This is my Public Key: ", public_key)