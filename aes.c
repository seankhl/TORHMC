#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <string>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

int aes_init(EVP_CIPHER_CTX *en_ctx, EVP_CIPHER_CTX *de_ctx)
{
    // generate a random 32-byte password
    unsigned char password[32];
    RAND_bytes(password, 32);

    // we temporarily need aes_key and aes_iv
    unsigned char aes_key[32], aes_iv[32];
    
    int z = EVP_BytesToKey(
                EVP_aes_256_cbc(), EVP_sha1(),  // 256-bit cbc; sha1 
                NULL,                           // salt
                password, 32,                    // password for generation
                8,                              // num rounds
                aes_key, aes_iv);               // return buffers
    
    // en_ctx stores the encryption key/iv
    EVP_CIPHER_CTX_init(en_ctx);
    
    EVP_EncryptInit_ex(en_ctx, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       aes_key, aes_iv);

    // de_ctx stores the decryption key/iv
    EVP_CIPHER_CTX_init(de_ctx);
    
    EVP_DecryptInit_ex(de_ctx, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       aes_key, aes_iv);
                       
  return 0;
}

#define AES_BLOCK_SIZE 128

unsigned char *aes_encrypt(EVP_CIPHER_CTX *en_ctx,
                           unsigned char *ptext, int *len)
{
    int outlen = *len + AES_BLOCK_SIZE;
    int finlen = 0;
    unsigned char *ctext = (unsigned char *)malloc(outlen);

    EVP_EncryptUpdate(en_ctx, ctext, &outlen, ptext, *len);
    EVP_EncryptFinal_ex(en_ctx, ctext+outlen, &finlen);

    *len = outlen + finlen;
    
    return ctext;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *de_ctx,
                           unsigned char *ctext, int *len)
{
    int outlen = *len;
    int finlen = 0;
  
    unsigned char *ptext = (unsigned char *)malloc(outlen);

    EVP_DecryptUpdate(de_ctx, ptext, &outlen, ctext, *len);        
    EVP_DecryptFinal_ex(de_ctx, ptext+outlen, &finlen);
  
    *len = outlen + finlen;
  
    return ptext;
}

unsigned char *randstr(unsigned char *str, int len, bool newseed=false)
{
    if (newseed) {
        timeval seed;
        gettimeofday(&seed, NULL);
        srand(seed.tv_usec * seed.tv_sec);
    }
    for (int i = 0; i < len; ++i) {
        str[i] = 'a' + (rand() % 26);
    }
    return str;
}

int main(int argc, char **argv)
{
    EVP_CIPHER_CTX en_ctx;    
    EVP_CIPHER_CTX de_ctx;

    if (aes_init(&en_ctx, &de_ctx)) {
        printf("Couldn't initialize AES System\n");
        return 1;
    }
    
    unsigned char msg[1024];
    int len = 1024;
    
    randstr(msg, len, true);

    unsigned char *ctext = aes_encrypt(&en_ctx, msg,   &len);
    unsigned char *ptext = aes_decrypt(&de_ctx, ctext, &len);

    string msgstr((char *)msg, 1024);

    if (memcmp(msg, ptext, len)) {
        printf("FAIL: enc/dec failed for \"%s\"\n", msgstr.c_str());
        return 0;
    }
    else {
        printf("OK: enc/dec ok for \"%s\"\n", msgstr.c_str());
    }
    
    EVP_CIPHER_CTX_cleanup(&en_ctx);
    EVP_CIPHER_CTX_cleanup(&de_ctx);
    
    free(ctext);
    free(ptext);
     
    return 0;
}
