#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
// get_iplist()
// get_pubkey(ISPADDR)

// broadcast_trusted_pubkey()

// random_path()

// create_connection_onion(vector<RSA> path)

// create_lightweight_onion(vector<aes_data> path);

using namespace std;

EVP_PKEY *get_pubkey(RSA *key)
{
    BIO* pubkey_bio = BIO_new_file("rsa_pubkey_bio.pem", "w");
    PEM_write_bio_RSAPublicKey(pubkey_bio, key);
    RSA* pubkey = RSA_new();
    PEM_read_bio_RSAPublicKey(pubkey_bio, &pubkey, NULL, NULL);
    BIO_free(pubkey_bio);
    
    EVP_PKEY *pubkey_evp = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubkey_evp, pubkey);
    return pubkey_evp;
}



EVP_PKEY *get_privkey(RSA *key)
{
    BIO* privkey_bio = BIO_new_file("rsa_privkey_bio.pem", "w");
    PEM_write_bio_RSAPrivateKey(privkey_bio, key, EVP_des_ede3_cbc(), NULL, 0, 0, (void *)"hello");
    RSA* privkey = RSA_new();
    PEM_read_bio_RSAPrivateKey(privkey_bio, &privkey, NULL, (void *)"hello");
    BIO_free(privkey_bio);
    
    EVP_PKEY *privkey_evp = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(privkey_evp, privkey);
    return privkey_evp;
}

unsigned char *rsa_encrypt(EVP_PKEY_CTX *en_ctx,
                           unsigned char *ptext, size_t *len)
{
    // initializie encryption process
    if (EVP_PKEY_encrypt_init(en_ctx) < 1) {
        // error
    }

    // padding initialization
    if (EVP_PKEY_CTX_set_rsa_padding(en_ctx, RSA_PKCS1_OAEP_PADDING) < 1) {
        // error
    }

    // determine output length
    size_t outlen;
    if (EVP_PKEY_encrypt(en_ctx, NULL, &outlen, ptext, *len) < 1) {
        // error
    }

    // get out buffer
    unsigned char *ctext = (unsigned char *)OPENSSL_malloc(outlen);
    if (!ctext) {
        // error
    }

    // 
    if (EVP_PKEY_encrypt(en_ctx, ctext, &outlen, ptext, *len) < 1) {
        // error
    }

    *len = outlen;

    return ctext;
}

unsigned char *rsa_decrypt(EVP_PKEY_CTX *de_ctx,
                           unsigned char *ctext, size_t *len)
{
    // initialize encryption process
    if (EVP_PKEY_decrypt_init(de_ctx) < 1) {
        // error
    }

    // padding initialization
    if (EVP_PKEY_CTX_set_rsa_padding(de_ctx, RSA_PKCS1_OAEP_PADDING) < 1) {
        // error
    }

    // determine output length
    size_t outlen;
    if (EVP_PKEY_decrypt(de_ctx, NULL, &outlen, ctext, *len) < 1) {
        // error
    }

    // get out buffer
    unsigned char *ptext = (unsigned char *)OPENSSL_malloc(outlen);
    if (!ctext) {
        // error
    }

    // perform encryption
    if (EVP_PKEY_encrypt(de_ctx, ptext, &outlen, ctext, *len) < 1) {
        // error
    }

    *len = outlen;

    return ptext;
}


int main(int argc, char **argv)
{
    RSA *rsa_rawkey;
    rsa_rawkey = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    int check_key = RSA_check_key(rsa_rawkey);
    while (check_key <= 0) {
        rsa_rawkey = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        check_key = RSA_check_key(rsa_rawkey);
    }

    EVP_PKEY *rsa_pubkey = get_pubkey(rsa_rawkey);
    EVP_PKEY_CTX *en_ctx;
    en_ctx = EVP_PKEY_CTX_new(rsa_pubkey, NULL);

    EVP_PKEY *rsa_privkey = get_privkey(rsa_rawkey);
    EVP_PKEY_CTX *de_ctx;
    de_ctx = EVP_PKEY_CTX_new(rsa_privkey, NULL);
    
    unsigned char msg[2560] = "ABCDEF";
    size_t len = 2559;

    unsigned char *ctext = rsa_encrypt(en_ctx, msg,   &len);
    unsigned char *ptext = rsa_decrypt(en_ctx, ctext, &len);

    string msgstr((char *)msg, len);

    if (memcmp(msg, ptext, len)) {
        printf("FAIL: enc/dec failed for \"%s\"\n", msgstr.c_str());
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
