import random
import multiprocessing as mp
import secrets
import time
import ecdsa
import binascii
import hashlib
import os

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

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
    b58_string = ''
    address_int = int(address_hex, 16)
    while address_int != 0:
        b58_string = alphabet[address_int % 58] + b58_string
        address_int //= 58
    return b58_string

def private_to_compressed_public(private_key):
    private_hex = binascii.unhexlify(private_key)
    priv = ecdsa.SigningKey.from_string(private_hex, curve=ecdsa.SECP256k1)
    return binascii.hexlify(priv.get_verifying_key().to_string(encoding='compressed'))

def public_to_address_coinye(public_key):
    public_key_bytes = binascii.unhexlify(public_key)
    # Run SHA256 for the public key
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run ripemd160 for the SHA256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = binascii.hexlify(ripemd160_bpk_digest)
    # Add network byte
    network_byte = b'0B'
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes = binascii.unhexlify(network_bitcoin_public_key)
    # Double SHA256 to get checksum
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = binascii.hexlify(sha256_2_nbpk_digest)
    checksum = sha256_2_hex[:8]
    # Concatenate public key and checksum to get the address
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    wallet = to_base58(address_hex)
    return wallet

def privateKey_to_WIF_coinye(pk):
    privWIF1 = hashlib.sha256(binascii.unhexlify('8b' + pk + '01')).hexdigest()
    privWIF2 = hashlib.sha256(binascii.unhexlify(privWIF1)).hexdigest()
    privWIF3 = '8b' + pk + '01' + privWIF2[:8]
    WIF = to_base58(privWIF3)
    return WIF

def make_coinye_address(kg):
    key = kg.generate_key()
    compressed_public_key = private_to_compressed_public(key)
    compressed_address = public_to_address_coinye(compressed_public_key)
    WIF_address = privateKey_to_WIF_coinye(key)
    return WIF_address, compressed_address

##def find_vanity(total, lock, process_name, vanity_prefix, seed=str(random.randbytes(256)), update_time=5, verbose=0):
##    wallet_address = 'ignore this junk its just a do while'
##    kg = KeyGenerator()
##    kg.seed_input(seed)
##
##    count = 0
##    last_count = 0
##    start_time = time.time()
##    this_time = time.time()
##
##    while wallet_address[1:len(vanity_prefix)+1].lower() != vanity_prefix:
##        if (time.time() - this_time) > update_time:
##            print(process_name,(count-last_count)/update_time,'H/s')
##            this_time, last_count = time.time(), count
##        count += 1
##        with lock:
##            total.value += 1
##        private_key,wallet_address = make_coinye_address(kg)
##    address_found = True
##    #print(process_name, count, time.time() - start_time)
##    print(process_name,total.value,count,time.time() - start_time,wallet_address,private_key)

def find_vanity(start_time, lock, process_name, vanity_prefix, update_time=5, verbose=0, seed=str(os.urandom(256))):
    print(f"[{process_name}]: started with seed {seed}")

    wallet_address = '00000000000000000000000000000000000000000000'
    kg = KeyGenerator()
    kg.seed_input(seed)
    
    while True:
        if wallet_address[1:len(vanity_prefix)+1].lower() == vanity_prefix:
            with lock:
                print(f"[{process_name}]: Found in {time.time() - start_time.value:.2f}s - {wallet_address} {private_key}")
                start_time.value = time.time()
        private_key,wallet_address = make_coinye_address(kg)
    
# now 3213 hashes a second at least
if __name__ == "__main__":

    # Create a shared value for the processes to all use
    #total = mp.Value('i', 0)
    #lock = mp.Lock()
    s_time = mp.Value('d', 0)
    lock = mp.Lock()
    with lock:
        s_time.value = time.time()
        print(f"Started at [{s_time.value}]")

    # Create process pool with four processes
    num_processes = mp.cpu_count()
    pool = mp.Pool(processes=num_processes) 
    processes = []

    prefix = "fish"
    #seed = str(os.urandom(256))
    update_time = 5
    verbose = 2

    # Initiate the worker processes
    for i in range(num_processes):
        # Set process name
        process_name = f'P{i}'
        # Create the process, and connect it to the worker function
        #new_process = mp.Process(target=find_vanity, args=(total,lock,process_name,prefix,seed,update_time,verbose))
        new_process = mp.Process(target=find_vanity, args=(s_time,lock,process_name,prefix,update_time,verbose))
        # Add new process to the list of processes
        processes.append(new_process)
        # Start the process
        new_process.start()
