#ifndef TORHMC_RSA_H
#define TORHMC_RSA_H

#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <string>
#include <sys/time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/bn.h>

using namespace std;

int write_pubkey(RSA *key, char *filepath);
EVP_PKEY *read_pubkey(char *filepath);

int write_privkey(RSA *key, char *filepath);
EVP_PKEY *read_privkey(char *filepath);

unsigned char *rsa_encrypt(EVP_PKEY_CTX *en_ctx,
                           unsigned char *ptext, size_t &len);
                           
unsigned char *rsa_decrypt(EVP_PKEY_CTX *de_ctx,
                           unsigned char *ctext, size_t &len);
                           
unsigned char *randstr(unsigned char *str, int len, bool newseed=false);

#endif // TORHMC_RSA_H
