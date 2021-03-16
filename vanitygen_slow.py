# -*- coding: utf-8 -*-
#
#    coineva vanitygen.py
#    Copyright (C) 2016 February
#    1200 Web Development
#    http://1200wd.com/
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
from bitcoin import encode_privkey, fast_multiply, pubkey_to_address, G
import timeit
import random
import multiprocessing
import binascii # importing binascii to be able to convert hexadecimal strings to binary data
import hashlib
import base58
import ecdsa

import psutil

def hex2wif(hex_key):

    # Step 1: here we have the private key
    # private_kic = hex_key
    # Step 2: let's add 80 in front of it
    extended_key = "80"+hex_key
    # Step 3: first SHA-256
    first_sha256 = hashlib.sha256(binascii.unhexlify(extended_key)).hexdigest()
    # Step 4: second SHA-256
    second_sha256 = hashlib.sha256(
        binascii.unhexlify(first_sha256)).hexdigest()
    # Step 5-6: add checksum to end of extended key
    final_key = extended_key+second_sha256[:8]
    # Step 7: finally the Wallet Import Format is the base 58 encode of final_key
    WIF = base58.b58encode(binascii.unhexlify(final_key))
    return WIF


def key_data(privkey):
    priv_key = encode_privkey(privkey, 'hex')
    # PRIVATE! SIGNING KEY ECDSA.SECP256k1
    sk = ecdsa.SigningKey.from_string(bytearray.fromhex(
        priv_key), curve=ecdsa.SECP256k1)
    # PUBLIC! VERIFYING KEY (64 BYTE LONG, MISSING 04 BYTE AT THE BEGINNING)
    vk = sk.verifying_key
    # FULL PUBLIC KEY
    # add 04 byte at the beginning
    pub_key = str(binascii.hexlify(b'\04'+vk.to_string()).decode())
    pid = os.getpid()
    wif_key = str(hex2wif(priv_key).decode())
    return priv_key, pub_key, pid, wif_key


def key_data_output(private_key, public_key, pid, wif_key, search_for, address, count, start):
    f = open('keys.txt', 'a')
    f.write("Searching for %s\n" % (search_for))
    f.write("Searched %d addresses in %d seconds (pid %d)\n" %
            (count, timeit.default_timer()-start, os.getpid()))
    f.write("Found address: %s\n" % address)
    f.write("This is my Uncompressed Public Key:\n%s\n" % public_key)
    f.write("Priv key HEX 80 Byte: 80%s\n" % private_key)
    f.write("WIF key: %s\n\n" % wif_key)
    f.close()

    # PRINTOUT KEYs DATA
    print("Searching for %s (pid %s)" % (search_for, pid))
    print("Searched %d in %d seconds (pid %d)" %
          (count, timeit.default_timer()-start, os.getpid()))
    print("Found address %s" % address)
    print("This is my Uncompressed Public Key:\n %s" % public_key)
    print("Priv key HEX 80 Byte: %s" % '80'+private_key)
    print("WIF key: %s" % wif_key)


def address_search(affinity,search_for='1Love'):
    proc = psutil.Process()  # get self pid
    print('PID: {pid}'.format(pid=proc.pid))
    aff = proc.cpu_affinity()
    print('Affinity before: {aff}'.format(aff=aff))
    proc.cpu_affinity(affinity)
    aff = proc.cpu_affinity()
    print('Affinity after: {aff}'.format(aff=aff))
    
    privkey = random.randrange(2**256)
    address = ''
    count = 0
    start = timeit.default_timer()

    print("Searching for %s (pid %s)" % (search_for, os.getpid()))
    while not search_for in address:
        privkey += 1
        pubkey_point = fast_multiply(G, privkey)
        address = pubkey_to_address(pubkey_point)
        count += 1
        if not count % 1000:
            print("Searched %d in %d seconds (pid %d)" %
                  (count, timeit.default_timer()-start, os.getpid()))

    private_key, public_key, pid, wif_key = key_data(privkey)
    key_data_output(private_key, public_key, pid,
                    wif_key, search_for, address, count, start)

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

