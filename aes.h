#ifndef TORHMC_AES_H
#define TORHMC_AES_H

#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <string>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_BLOCK_SIZE 128

using namespace std;

struct aes_data {
    unsigned char aes_key[32];
    unsigned char aes_iv[32];
};

aes_data aes_create();

int aes_init(EVP_CIPHER_CTX *en_ctx, EVP_CIPHER_CTX *de_ctx);

unsigned char *aes_encrypt(EVP_CIPHER_CTX *en_ctx,
                           unsigned char *ptext, int *len);

unsigned char *aes_decrypt(EVP_CIPHER_CTX *de_ctx,
                           unsigned char *ctext, int *len);
                           
#endif // TORHMC_AES_H
