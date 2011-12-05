#include "rsa.h"

using namespace std;

int write_pubkey(RSA *key, string filepath)
{
    BIO *pubkey_bio = BIO_new_file(filepath.c_str(), "w");
    BIO_set_mem_eof_return(pubkey_bio, 0);
    PEM_write_bio_RSAPublicKey(pubkey_bio, key);
    BIO_free(pubkey_bio);
    return 1;
}

EVP_PKEY *read_pubkey(string filepath)
{
    RSA *pubkey = RSA_new();
    BIO *pubkey_bio = BIO_new_file(filepath.c_str(), "r");
    PEM_read_bio_RSAPublicKey(pubkey_bio, &pubkey, 0, NULL);
    BIO_free(pubkey_bio);
    
    EVP_PKEY *pubkey_evp = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubkey_evp, pubkey);
    return pubkey_evp;
}

int write_privkey(RSA *key, string filepath)
{
    BIO *privkey_bio = BIO_new_file(filepath.c_str(), "w");
    BIO_set_mem_eof_return(privkey_bio, 0);
    PEM_write_bio_RSAPrivateKey(privkey_bio, key, NULL, NULL, 0, 0, NULL);
    BIO_free(privkey_bio);
    return 1;
}

EVP_PKEY *read_privkey(string filepath)
{
    RSA *privkey = RSA_new();
    BIO *privkey_bio = BIO_new_file(filepath.c_str(), "r");
    PEM_read_bio_RSAPrivateKey(privkey_bio, &privkey, 0, NULL);
    BIO_free(privkey_bio);
    
    EVP_PKEY *privkey_evp = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(privkey_evp, privkey);
    return privkey_evp;
}

unsigned char *rsa_encrypt(EVP_PKEY_CTX *en_ctx,
                           unsigned char *ptext, size_t &len)
{
    // initializie encryption process
    if (EVP_PKEY_encrypt_init(en_ctx) < 1) {
        return NULL;
    }

    // padding initialization
    if (EVP_PKEY_CTX_set_rsa_padding(en_ctx, RSA_PKCS1_OAEP_PADDING) < 1) {
        return NULL;
    }

    // determine output length
    size_t outlen;
    if (EVP_PKEY_encrypt(en_ctx, NULL, &outlen, ptext, len) < 1) {
        return NULL;
    }
    
    // get out buffer
    unsigned char *ctext = (unsigned char *)OPENSSL_malloc(outlen);
    if (!ctext) {
        return NULL;
    }

    // perform encryption
    if (EVP_PKEY_encrypt(en_ctx, ctext, &outlen, ptext, len) < 1) {
        return NULL;
    }

    len = outlen;

    return ctext;
}

unsigned char *rsa_decrypt(EVP_PKEY_CTX *de_ctx,
                           unsigned char *ctext, size_t &len)
{
    // initialize encryption process
    if (EVP_PKEY_decrypt_init(de_ctx) < 1) {
        return NULL;
    }

    // padding initialization
    if (EVP_PKEY_CTX_set_rsa_padding(de_ctx, RSA_PKCS1_OAEP_PADDING) < 1) {
        return NULL;
    }

    // determine output length
    size_t outlen;
    if (EVP_PKEY_decrypt(de_ctx, NULL, &outlen, ctext, len) < 1) {
        return NULL;
    }

    // get out buffer
    unsigned char *ptext = (unsigned char *)OPENSSL_malloc(outlen);
    if (!ptext) {
        return NULL;
    }

    // perform decryption
    if (EVP_PKEY_decrypt(de_ctx, ptext, &outlen, ctext, len) < 1) {
        return NULL;
    }

    len = outlen;

    return ptext;
}

unsigned char *randstr(unsigned char *str, int len, bool newseed)
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
/*
int main(int argc, char **argv)
{
    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    RSA *rsa_rawkey;
    rsa_rawkey = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    int check_key = RSA_check_key(rsa_rawkey);
    while (check_key <= 0) {
        rsa_rawkey = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        check_key = RSA_check_key(rsa_rawkey);
    }
    write_pubkey(rsa_rawkey, "pubkey1.pem");
    write_privkey(rsa_rawkey, "privkey1.pem");
    
    RSA *rsa_rawkey2;
    rsa_rawkey2 = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    int check_key2 = RSA_check_key(rsa_rawkey2);
    while (check_key2 <= 0) {
        rsa_rawkey2 = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        check_key2 = RSA_check_key(rsa_rawkey2);
    }
    write_pubkey(rsa_rawkey2, "pubkey2.pem");
    write_privkey(rsa_rawkey2, "privkey2.pem");
}
*/
int main(int argc, char **argv)
{
    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    RSA *rsa_rawkey;
    rsa_rawkey = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    int check_key = RSA_check_key(rsa_rawkey);
    while (check_key <= 0) {
        rsa_rawkey = RSA_generate_key(1024, RSA_F4, NULL, NULL);
        check_key = RSA_check_key(rsa_rawkey);
    }
    
    //EVP_PKEY *rsa_pubkey = get_pubkey(rsa_rawkey);
    
    EVP_PKEY *rsa_pubkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(rsa_pubkey, rsa_rawkey);
    
    EVP_PKEY_CTX *en_ctx;
    ENGINE *e = ENGINE_get_default_RSA();
    ENGINE_init(e);
    en_ctx = EVP_PKEY_CTX_new(rsa_pubkey, e);

    //EVP_PKEY *rsa_privkey = get_privkey(rsa_rawkey);

    EVP_PKEY *rsa_privkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(rsa_privkey, rsa_rawkey);
    
    EVP_PKEY_CTX *de_ctx;
    ENGINE *f = ENGINE_get_default_RSA();
    ENGINE_init(f);
    de_ctx = EVP_PKEY_CTX_new(rsa_privkey, f);
    
    unsigned char msg[86];
    size_t len = 86;
    
    randstr(msg, len, true);

    unsigned char *ctext = rsa_encrypt(en_ctx, msg,   len);   
    printf("%d\n",len); 
    unsigned char *ptext = rsa_decrypt(de_ctx, ctext, len);
    printf("%d\n",len); 

    string msgstr((char *)msg, len);
    string ptextstr((char *)ptext, len);

    if (memcmp(msg, ptext, len)) {
        printf("FAIL: enc/dec failed for \"%s\"\n", ptextstr.c_str());
        return 0;
    }
    else {
        printf("OK: enc/dec ok for \"%s\"\n", msgstr.c_str());
    }

    EVP_PKEY_CTX_free(en_ctx);
    EVP_PKEY_CTX_free(de_ctx);

    free(ctext);
    free(ptext);

    return 0;
}

