#include "aes.h"

using namespace std;

aes_data aes_create()
{
    // generate a random 32-byte password
    unsigned char password[32];
    RAND_bytes(password, 32);
    
    // we pass data via an aes_data struct
    aes_data data;
    
    int z = EVP_BytesToKey(
                EVP_aes_256_cbc(), EVP_sha1(),  // 256-bit cbc; sha1 
                NULL,                           // salt
                password, 32,                   // password for generation
                8,                              // num rounds
                data.aes_key, data.aes_iv);     // return buffers
    
    return data;
}

int aes_init(EVP_CIPHER_CTX *en_ctx, EVP_CIPHER_CTX *de_ctx, const aes_data &data)
{
    // en_ctx stores the encryption key/iv
    EVP_CIPHER_CTX_init(en_ctx);
    
    EVP_EncryptInit_ex(en_ctx, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       data.aes_key, data.aes_iv);

    // de_ctx stores the decryption key/iv
    EVP_CIPHER_CTX_init(de_ctx);
    
    EVP_DecryptInit_ex(de_ctx, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       data.aes_key, data.aes_iv);
                       
    return 0;
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *en_ctx,
                           unsigned char *ptext, int *len)
{
    int outlen = *len + AES_BLOCK_SIZE;
    int finlen = 0;
    unsigned char *ctext = (unsigned char *)OPENSSL_malloc(outlen);

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
  
    unsigned char *ptext = (unsigned char *)OPENSSL_malloc(outlen);

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
    aes_data data = aes_create();
    
    for (int i = 0; i < 2; ++i) {
    if (aes_init(&en_ctx, &de_ctx, data)) {
        printf("Couldn't initialize AES System\n");
        return 1;
    }
    unsigned char msg[1041];
    int len = 1025;
    
    randstr(msg, len, true);
    unsigned char msgorig[1041];
    memcpy(msgorig, msg, len);

    unsigned char *ctext = aes_encrypt(&en_ctx, msg, &len);
    memcpy(msg, ctext, len);
    cerr << len << endl;
    
    unsigned char *ptext = aes_decrypt(&de_ctx, msg, &len);
    cerr << len << endl;

    string msgstr((char *)msgorig, len);

    if (memcmp(msgorig, ptext, len)) {
        printf("FAIL: enc/dec failed for \"%s\"\n", msgstr.c_str());
        return 0;
    }
    else {
        printf("OK: enc/dec ok for \"%s\"\n", msgstr.c_str());
    }
    
    EVP_CIPHER_CTX_cleanup(&en_ctx);
    EVP_CIPHER_CTX_cleanup(&de_ctx);
    }
    
    //free(ctext);
    //free(ptext);

    return 0;
}

