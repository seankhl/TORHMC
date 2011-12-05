/*
   CS 181a Final Project - Onion Router Client
   Chris Beavers and Sean Laguna
   Based on C sockets tutorial code from
   http://www.linuxhowtos.org/C_C++/socket.htm
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


#include <iostream>
#include <cstring>
#include <string>
#include <sys/time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

using namespace std;

/////////////////////////////////////////////////////////////////
/* AES functions                                               */
/////////////////////////////////////////////////////////////////

#define AES_BLOCK_SIZE 128

struct aes_data {
    unsigned char aes_key[32];
    unsigned char aes_iv[32];
};

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

/////////////////////////////////////////////////////////////////
/* RSA functions                                               */
/////////////////////////////////////////////////////////////////

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

/////////////////////////////////////////////////////////////////
/* Client functions                                            */
/////////////////////////////////////////////////////////////////

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int ipToInt(char * ip)
{
    int a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    return ((a & 0xFF) << 24) + ((b & 0xFF) << 16) + ((c & 0xFF) << 8) + (d & 0xFF);
}

char * intToIp(int i)
{
    static char ip[128];

    int a, b, c, d;
    a = (i >> 24) & 0xFF;
    b = (i >> 16) & 0xFF;
    c = (i >> 8) & 0xFF;
    d = i & 0xFF;
    sprintf(ip, "%u.%u.%u.%u", a, b, c, d);
    return ip;
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    int bufferSize = 512;
    int numNodes = 2;
    int layerSize = 128;
    unsigned char buffer[bufferSize];
    if (argc < 3) {
       fprintf(stderr,"usage: %s hostname port\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    bzero(buffer,bufferSize);

    printf("Randomly selecting path...");
    char* ips[2]       = {"127.0.0.1", "127.0.0.1"};
    string keypaths[2] = {"keys/pubkey2.pem","keys/pubkey2.pem"};
    short ports[2]     = {51716,51718};

    // Set up symmetric keys and encryption/decryption contexts
    aes_data symmkeys[numNodes];
    EVP_CIPHER_CTX en_ctx[numNodes];
    EVP_CIPHER_CTX de_ctx[numNodes];
    for(size_t j=0; j < numNodes; j++)
    {
        symmkeys[j] = aes_create();
        if (aes_init(&(en_ctx[j]), &(de_ctx[j]), symmkeys[j])) {
            printf("Couldn't initialize AES System\n");
            return 1;
        }
    }
    printf("DONE!\n");

    printf("Creating onion...");

    int i=0;
    for(i=numNodes - 1; i >= 0; i--)
    {
        unsigned char layer[layerSize];
        bzero(layer, layerSize);

        int ipint = ipToInt(ips[i]);
        short portshort = ports[i];

        memcpy(layer, (char *) &ipint, sizeof(int));
        memcpy(layer + sizeof(int), (char *) &portshort, sizeof(short));
        memcpy(layer + sizeof(int) + sizeof(short), (char *) &symmkeys[i], sizeof(aes_data));

        EVP_PKEY* pub = read_pubkey(keypaths[i]);
        EVP_PKEY_CTX *en_ctx;
        ENGINE *e = ENGINE_get_default_RSA();
        ENGINE_init(e);
        en_ctx = EVP_PKEY_CTX_new(pub, e);
        size_t len = 86;
        unsigned char * ctext = rsa_encrypt(en_ctx, layer, len);
        if(len == layerSize)
            memcpy(buffer + i*layerSize, ctext, layerSize);
        else
            printf("everything is fucked!: %d\n", len);
    }
    printf("DONE!\nEstablishing symmetric encryption through the path...");

    printf("message: %s\n\n", buffer);
    n = write(sockfd,buffer,bufferSize);
    if (n < 0) 
         error("ERROR writing to socket");

    bzero(buffer, bufferSize);
    n = read(sockfd,buffer,bufferSize);
    printf("DONE!\nResponse from exit node: %s\nAnonymous network connection established. ", buffer);

    while (1) {
        printf("Who do you want to ping? ");
        unsigned char message[bufferSize];
        bzero((char *) message,bufferSize);
        fgets((char *) message,255,stdin);

        // Encrypt buffer with symmetric keys - NOTE: adds ~16 bytes per layer
        int len = strlen((char *) message);
        for(i=numNodes - 1; i >= 0; i--)
        {
            printf("About to encrypt %d bytes: %s\n", len, (char *) message);
            unsigned char * ctext = aes_encrypt(&(en_ctx[i]), message, &len);
            memcpy(message, ctext, len);
            printf("message size: %d...%s\n", len, (char *) message);
        }

        // Relay down the path
        n = write(sockfd,message,len);
        if (n < 0) 
             error("ERROR writing to socket");
        bzero(buffer,bufferSize);

        // Wait for response
        n = read(sockfd,buffer,bufferSize);

        // Decrypt buffer with symmetric keys in reverse order
        if (n < 0) error("ERROR reading from socket");
        printf("Response from server: %s\n", buffer);
    }
    close(sockfd);
    return 0;
}
