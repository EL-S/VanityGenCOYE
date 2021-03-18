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
    output.insert(0, 2- output.length(), '0');
    return output;
}

string sha256(string line) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, line.c_str(), line.length());
    SHA256_Final(hash, &sha256);

    string output = "";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        output += to_hex(hash[i]);
    }
    return output;
}

string sha256_different(string strHex) {
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

string ripemd160(string line)
{
    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, line.c_str(), line.length());
    RIPEMD160_Final(hash, &ripemd160);

    string output = "";
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        output += to_hex(hash[i]);
    }
    return output;

    //for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++)
    //{
    //    sprintf_s(outputBuffer + (i * 2), sizeof(outputBuffer + (i * 2)), "%02x", hash[i]);
    //}
    //outputBuffer[40] = 0;
}

std::vector<char> HexToBytes(const std::string& hex) {
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

string privateKey_to_WIF_coinye(string pk) {
    string base = "8b" + pk + "01";
    cout << base << endl;
    string privWIF1 = sha256_different(base);
    cout << privWIF1 << endl;
    string privWIF2 = sha256_different(privWIF1);
    cout << privWIF2 << endl;
    string privWIF3 = base + privWIF2.substr(0, 8);
    cout << privWIF3 << endl;
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
    string network_bitcoin_public_key = "0b" + ripemd160(sha256_different(compressed_pk));
    string sha256_2_hex = sha256_different(sha256_different(network_bitcoin_public_key));
    string checksum = sha256_2_hex.substr(0, 8);
    std::string address_hex = network_bitcoin_public_key + checksum;
    const char* phex = address_hex.c_str();
    std::string ret = b58(phex);
    return ret;
}

int main()
{

    // This is the same as
    // compressed_public_key = private_to_compressed_public(key)
    std::string private_key = "1af67944a84a800ac9a96a59c4a7934988e3ef93a850a1d5ff219661c12c37c4";
    cout << private_key << endl;

    string compressed_public_key = private_to_compressed_public(private_key);
    cout << compressed_public_key << endl;

    string compressed_address = public_to_address_coinye(compressed_public_key);
    cout << compressed_address << endl;

    string WIF_address = privateKey_to_WIF_coinye(private_key);
    cout << WIF_address << endl;

    return 0;
}

/*
bool EC_KEY_regenerate_key(EC_KEY* p_key, BIGNUM* p_priv_key)
{
    bool okay = false;

    BN_CTX* p_ctx = 0;
    EC_POINT* p_pub_key = 0;

    if (p_key)
    {
        const EC_GROUP* p_group = EC_KEY_get0_group(p_key);

        if ((p_ctx = BN_CTX_new()) != 0)
        {
            p_pub_key = EC_POINT_new(p_group);

            if (p_pub_key)
            {
                if (EC_POINT_mul(p_group, p_pub_key, p_priv_key, 0, 0, p_ctx))
                {
                    EC_KEY_set_public_key(p_key, p_pub_key);
                    EC_KEY_set_private_key(p_key, p_priv_key);

                    okay = true;
                }

                EC_POINT_free(p_pub_key);
            }

            BN_CTX_free(p_ctx);
        }
    }

    return okay;
}
*/