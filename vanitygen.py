import time
import random
import secrets
import codecs
import hashlib
import ecdsa

import binascii
import sys

import base58

import multiprocessing
import psutil

class KeyGenerator:
    def __init__(self):
        self.POOL_SIZE = 256
        self.KEY_BYTES = 32
        self.CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
        self.pool = [0] * self.POOL_SIZE
        self.pool_pointer = 0
        self.prng_state = None
        self.__init_pool()
        
    def seed_input(self, str_input):
        time_int = int(time.time())
        self.__seed_int(time_int)
        for char in str_input:
            char_code = ord(char)
            self.__seed_byte(char_code)
            
    def generate_key(self):
        big_int = self.__generate_big_int()
        big_int = big_int % (self.CURVE_ORDER - 1) # key < curve order
        big_int = big_int + 1 # key > 0
        key = hex(big_int)[2:]
        # Add leading zeros if the hex key is smaller than 64 chars
        key = key.zfill(self.KEY_BYTES * 2)
        return key

    def __init_pool(self):
        for i in range(self.POOL_SIZE):
            random_byte = secrets.randbits(8)
            self.__seed_byte(random_byte)
        time_int = int(time.time())
        self.__seed_int(time_int)

    def __seed_int(self, n):
        self.__seed_byte(n)
        self.__seed_byte(n >> 8)
        self.__seed_byte(n >> 16)
        self.__seed_byte(n >> 24)

    def __seed_byte(self, n):
        self.pool[self.pool_pointer] ^= n & 255
        self.pool_pointer += 1
        if self.pool_pointer >= self.POOL_SIZE:
            self.pool_pointer = 0
    
    def __generate_big_int(self):
        if self.prng_state is None:
            seed = int.from_bytes(self.pool, byteorder='big', signed=False)
            random.seed(seed)
            self.prng_state = random.getstate()
        random.setstate(self.prng_state)
        big_int = random.getrandbits(self.KEY_BYTES * 8)
        self.prng_state = random.getstate()
        return big_int

def to_base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

def generate_address(private_key):
    public_key = private_to_public(private_key)
    address = public_to_address(public_key)
    return address
        
def generate_compressed_address(private_key):
    public_key = private_to_compressed_public(private_key)
    address = public_to_address(public_key)
    return address

def private_to_public(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    # Add bitcoin byte
    bitcoin_byte = b'04'
    public_key = bitcoin_byte + key_hex
    return public_key

def private_to_compressed_public(private_key):
    private_hex = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(private_hex, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    # Get X from the key (first half)
    key_string = key_hex.decode('utf-8')
    half_len = len(key_hex) // 2
    key_half = key_hex[:half_len]
    # Add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
    last_byte = int(key_string[-1], 16)
    bitcoin_byte = b'02' if last_byte % 2 == 0 else b'03'
    public_key = bitcoin_byte + key_half
    return public_key

def public_to_address(public_key):
    public_key_bytes = codecs.decode(public_key, 'hex')
    # Run SHA256 for the public key
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run ripemd160 for the SHA256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    # Add network byte
    network_byte = b'00'
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
    # Double SHA256 to get checksum
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    # Concatenate public key and checksum to get the address
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    wallet = to_base58(address_hex)
    return wallet

def public_to_address_coinye(public_key):
    public_key_bytes = codecs.decode(public_key, 'hex')
    # Run SHA256 for the public key
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run ripemd160 for the SHA256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    # Add network byte
    network_byte = b'0B'
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
    # Double SHA256 to get checksum
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    # Concatenate public key and checksum to get the address
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    wallet = to_base58(address_hex)
    return wallet

def privateKey_to_WIF(pk): #wallet import format ==> pra importar nas carteiras

    privWIF1 = hashlib.sha256(binascii.unhexlify('80' + pk)).hexdigest()
    privWIF2 = hashlib.sha256(binascii.unhexlify(privWIF1)).hexdigest()
    privWIF3 = '80' + pk + privWIF2[:8]

    pubnum = int(privWIF3, 16)
    pubnumlist = []
    while pubnum != 0:
        pubnumlist.append(pubnum % 58)
        pubnum //= 58
    WIF = ''
    #print(pubnumlist)
    for l in ['123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[x] for x in pubnumlist]:
        WIF = l + WIF
    #print(WIF)
    return WIF

def privateKey_to_WIF_coinye(pk): #wallet import format ==> pra importar nas carteiras

    privWIF1 = hashlib.sha256(binascii.unhexlify('8b' + pk + '01')).hexdigest()
    privWIF2 = hashlib.sha256(binascii.unhexlify(privWIF1)).hexdigest()
    privWIF3 = '8b' + pk + '01' + privWIF2[:8]

    pubnum = int(privWIF3, 16)
    pubnumlist = []
    while pubnum != 0:
        pubnumlist.append(pubnum % 58)
        pubnum //= 58
    WIF = ''
    #print(pubnumlist)
    for l in ['123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[x] for x in pubnumlist]:
        WIF = l + WIF
    #print(WIF)
    return WIF

def WIF_to_privateKey(wif):
    private_key_WIF = wif
    first_encode = base58.b58decode(private_key_WIF)
    private_key_full = binascii.hexlify(first_encode)
    private_key = private_key_full[2:-8]
    return private_key

def WIF_to_privateKey_coinye(wif):
    private_key_WIF = wif
    first_encode = base58.b58decode(private_key_WIF)
    private_key_full = binascii.hexlify(first_encode)
    private_key = private_key_full[2:-10]
    return private_key

def make_coinye_address(kg):
    key = kg.generate_key()
    compressed_public_key = private_to_compressed_public(key)
    compressed_address = public_to_address_coinye(compressed_public_key)
    rs =  privateKey_to_WIF_coinye(key)
    return rs,compressed_address


def address_search(affinity):
    proc = psutil.Process()  # get self pid
    print('PID: {pid}'.format(pid=proc.pid))
    aff = proc.cpu_affinity()
    print('Affinity before: {aff}'.format(aff=aff))
    proc.cpu_affinity(affinity)
    aff = proc.cpu_affinity()
    print('Affinity after: {aff}'.format(aff=aff))
    
    seed = 'jmLkYVbWfQpcWinsrxfOnMknrXGeAomHKjJ3pNtJop1K6SwLOcYkgK0wV8nve2A0a08QOQpi4GkbuZnCRHjZwj28j8GAfpHpddGTpVGHn42itcYgZ7423yyTwFSvY31vti4HC8YlzpcYhnlf1cvb7PYBa3QghemjWOtRIZjgvW7AQX8HRpeLxFib4VxhWqYE7FO7zZzBAaQu09WsbfBJTi5ZsM16JMSbEuHozKV68SFQHRnvYiT0hjQJ3ovYgdaZQPBwfgpLbLSvcrtlstQAA1JdUWC8bKH1owReM6xtMdgNhKtYQNQOb0XARQPhGbH4WJ3LssPbjjxB9sEogn83zGQQtfTWqtrLRL7hrRxODbTe0l0f6ThlW2oXS8xFEu3BhRNa6togtuOoKbsaPGE4cD7o0yzDJ90geuRo92YuPROhTE0bq8sLWpxdShdHwEp'
    wallet_address = '5WQSHkPRWHSTfhr2TWiQNM2b8VKqkPTiNr'
    prefix = 'coinye'

    prefix_lower = prefix.lower()
    kg = KeyGenerator()
    kg.seed_input(seed)

    while wallet_address[1:len(prefix)+1].lower() != prefix_lower:
        private_key,wallet_address = make_coinye_address(kg)

    print(wallet_address,private_key)

def spawn():
    procs = list()
    n_cpus = psutil.cpu_count()
    for cpu in range(n_cpus):
        affinity = [cpu]
        d = dict(affinity=affinity)
        p = multiprocessing.Process(target=address_search, kwargs=d)
        p.start()
        procs.append(p)
    for p in procs:
        p.join()
        print('joined')

if __name__ == '__main__':
    spawn()

