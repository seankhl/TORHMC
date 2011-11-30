#include <openssl/rsa.h>
#include <openssl/evp.h>

RSA make_pubkey(BIGNUM *n, BIGNUM *e)
{
    RSA ret;
    ret->n = n;
    ret->e = e;
    return ret;
}

// get_iplist()
// get_pubkey(ISPADDR)

// broadcast_trusted_pubkey()

// random_path()

// create_connection_onion(vector<RSA> path)

// create_lightweight_onion(vector<aes_data> path);

int do_evp_seal(*RSA rsa_pkey, FILE *in_file, FILE *out_file)
{
    int retval = 0;
    

    EVP_PKEY_CTX *p_ctx;
    EVP_PKEY *pkey = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(p_ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(p_ctx, 2048);
    /* Generate key */
    EVP_PKEY_keygen(p_ctx, &pkey);
    
    EVP_CIPHER_CTX ctx;
    unsigned char buffer[4096];
    unsigned char buffer_out[4096 + EVP_MAX_IV_LENGTH];
    size_t len;
    int len_out;
    unsigned char *ek;
    int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    EVP_CIPHER_CTX_init(&ctx);
    ek = malloc(EVP_PKEY_size(pkey));


    out_free:
    EVP_PKEY_free(pkey);
    free(ek);

    out:
    return retval;
}



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
    PEM_write_bio_RSAPrivateKey(privkey_bio, key);
    RSA* privkey = RSA_new();
    PEM_read_bio_RSAPrivateKey(privkey_bio, &pubkey, NULL, NULL);
    BIO_free(privkey_bio);
    
    EVP_PKEY *privkey_evp = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(privkey_evp, privkey);
    return pkey_evp;
}

int main(int argc, char **argv)
{
    RSA *rsa_privatekey;
    unsigned char cleartext[2560] = "ABCDEF";
    unsigned char encrypted[2560] = { 0 };
    unsigned char decrypted[2560] = { 0 };
    int resultEncrypt = 0;
    int resultDecrypt = 0;

    rsa_key = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    int check_key = RSA_check_key(rsa_key);
    
    while (check_key <= 0) {
        rsa_key = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        check_key = RSA_check_key(rsa_key);
    }
    
    BIO* rsa_pubkey_bio = BIO_new_file("rsapublickey.pem", "w");
    PEM_write_bio_RSAPublicKey(rsa_pubkey_bio, rsa_privkey);
    RSA* rsa_pubkey = RSA_new();
    PEM_read_bio_RSAPublicKey(rsa_pub_bio, &rsa_pubkey, NULL, NULL);
    BIO_free(rsa_pubkey_bio);
    
    resultEncrypt = RSA_public_encrypt(6, cleartext, encrypted, myRSA, RSA_PKCS1_OAEP_PADDING);
    printf("%d rsasize.\n", RSA_size(myRSA));
    printf("%d from encrypt.\n", resultEncrypt);
    resultDecrypt = RSA_private_decrypt( 128, encrypted, decrypted, myRSA, RSA_PKCS1_OAEP_PADDING);
    printf("%d from decrypt: '%s'\n", resultDecrypt, decrypted);
    RSA_free ( myRSA );

    return 0;
}
