// VanityGenCoinyeSimple.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include "openssl/sha.h"
#include "openssl/ripemd.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

using namespace std;

// calculates and returns the public key associated with the given private key
// - input private key and output public key are in hexadecimal
// form = POINT_CONVERSION_[UNCOMPRESSED|COMPRESSED|HYBRID]
char* priv2pub(const char* priv_hex,
    point_conversion_form_t form)
{
    // create group
    EC_GROUP* ecgrp = EC_GROUP_new_by_curve_name(NID_secp256k1);

    // convert priv key from hexadecimal to BIGNUM
    BIGNUM* priv_bn = BN_new();
    BN_hex2bn(&priv_bn, priv_hex);

    // compute pub key from priv key and group
    EC_POINT* pub = EC_POINT_new(ecgrp);
    EC_POINT_mul(ecgrp, pub, priv_bn, NULL, NULL, NULL);

    // convert pub_key from elliptic curve coordinate to hexadecimal
    char* ret = EC_POINT_point2hex(ecgrp, pub, form, NULL);

    EC_GROUP_free(ecgrp); BN_free(priv_bn); EC_POINT_free(pub);

    return ret;
}

std::string b58(const char* priv_hex)
{
    char table[] = { '1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z' };

    BIGNUM* base58 = NULL;

    BIGNUM* resultExp = BN_new();
    BIGNUM* resultAdd = BN_new();
    BIGNUM* resultRem = BN_new();
    BN_CTX* bn_ctx = BN_CTX_new();

    BN_dec2bn(&base58, "58");

    std::string endresult;
    std::vector<int> v;

    BN_hex2bn(&resultAdd, priv_hex);

    while (!BN_is_zero(resultAdd)) {
        BN_div(resultAdd, resultRem, resultAdd, base58, bn_ctx);
        char* asdf = BN_bn2dec(resultRem);
        v.push_back(atoi(asdf));
    }

    for (int i = (int)v.size() - 1; i >= 0; i--) {
        endresult = endresult + table[v[i]];
    }

    BN_free(resultAdd);
    BN_free(resultExp);
    BN_free(resultRem);
    BN_CTX_free(bn_ctx);

    return endresult;
}

string to_hex(unsigned char s) {
    stringstream ss;
    ss << hex << (int)s;
    string output = ss.str();
    output.insert(0, 2 - output.length(), '0');
    return output;
}

string sha256(string strHex) {
    // convert to blob. returns dynamic memory allocated with
    //  OPENSSL_malloc. Use OPENSSL_free to destroy it.
    long len = 0;
    unsigned char* bin = OPENSSL_hexstr2buf(strHex.c_str(), &len);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, bin, len);
    SHA256_Final(hash, &sha256);

    // free the input data.
    OPENSSL_free(bin);

    string output = "";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        output += to_hex(hash[i]);
    }

    return output;
}

string ripemd160(string strHex) {
    // convert to blob. returns dynamic memory allocated with
    //  OPENSSL_malloc. Use OPENSSL_free to destroy it.
    long len = 0;
    unsigned char* bin = OPENSSL_hexstr2buf(strHex.c_str(), &len);

    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, bin, len);
    RIPEMD160_Final(hash, &ripemd160);

    // free the input data.
    OPENSSL_free(bin);

    string output = "";
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        output += to_hex(hash[i]);
    }

    return output;
}

string privateKey_to_WIF_coinye(string pk) {
    string base = "8b" + pk + "01";
    string privWIF1 = sha256(base);
    string privWIF2 = sha256(privWIF1);
    string privWIF3 = base + privWIF2.substr(0, 8);
    const char* phex = privWIF3.c_str();
    std::string ret = b58(phex);
    return ret;
}

string private_to_compressed_public(string pk) {
    const char* private_key_char = pk.c_str();
    char* pub_hex = priv2pub(private_key_char, POINT_CONVERSION_COMPRESSED);
    return pub_hex;
    //free(pub_hex)
}

string public_to_address_coinye(string compressed_pk) {
    string network_bitcoin_public_key = "0b" + ripemd160(sha256(compressed_pk));
    string sha256_2_hex = sha256(sha256(network_bitcoin_public_key));
    string checksum = sha256_2_hex.substr(0, 8);
    std::string address_hex = network_bitcoin_public_key + checksum;
    const char* phex = address_hex.c_str();
    std::string ret = b58(phex);
    return ret;
}

void make_coinye_address(string* private_key, string* compressed_address) {
    unsigned char rnd[32];
    RAND_bytes(rnd, sizeof(rnd));

    *private_key = "";
    for (int i = 0; i < sizeof(rnd); i++) {
        *private_key += to_hex(rnd[i]);
    }
    string compressed_public_key = private_to_compressed_public(*private_key);
    *compressed_address = public_to_address_coinye(compressed_public_key);
    //free(compressed_public_key);
    return;
}

bool iequals(const string& a, const string& b)
{
    return std::equal(a.begin(), a.end(),
        b.begin(), b.end(),
        [](char a, char b) {
            return tolower(a) == tolower(b);
        });
}

string find_vanity(string vanity_prefix) {
    string private_key;
    string wallet_address;
    int prefix_len = vanity_prefix.length();
    do {
        make_coinye_address(&private_key, &wallet_address);
    }
    while (!iequals(wallet_address.substr(1, prefix_len), vanity_prefix));
    //while (wallet_address.compare(1, prefix_len, vanity_prefix));
    return private_key;
}

int main()
{
    string private_key = find_vanity("gay");
    string compressed_public_key = private_to_compressed_public(private_key);
    string compressed_address = public_to_address_coinye(compressed_public_key);
    string WIF_address = privateKey_to_WIF_coinye(private_key);
    cout << compressed_address << endl;
    cout << WIF_address << endl;

    return 0;
}