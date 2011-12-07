/*
   CS 181a Final Project - Onion Router Node
   Chris Beavers and Sean Laguna
   Based on C sockets tutorial code from
   http://www.linuxhowtos.org/C_C++/socket.htm
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
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

// SERVER CODE

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

/******** DOSTUFF() *********************
 There is a separate instance of this function 
 for each connection.  It handles all communication
 once a connnection has been established.
 *****************************************/
void dostuff(int sock)
{   
    // some consts for us
    int bufferSize = 512;
    int layerSize = 128;
    
    // set up the buffer
    unsigned char buffer[bufferSize];
    bzero(buffer, bufferSize);
    
    // read in the data
    int n = 0;
    n = read(sock, buffer, bufferSize);
    
    // read in our layer
    unsigned char layer[layerSize];
    bzero(layer, layerSize);
    memcpy(layer, buffer, layerSize);

    /* now decrypt our layer with our private key */
    
    // set up engine
    ENGINE *f = ENGINE_get_default_RSA();
    ENGINE_init(f);
    
    // read in the private key and set up a context with it
    EVP_PKEY *priv = read_privkey("privkey.pem");
    EVP_PKEY_CTX *de_ctx;
    de_ctx = EVP_PKEY_CTX_new(priv, f);

    // perform decryption
    size_t len = layerSize;
    unsigned char *ptext = rsa_decrypt(de_ctx, layer, len);
    
    // extract our AES symmetric encryption struct
    aes_data symkey;
    bzero((char *)&symkey, sizeof(aes_data));
    memcpy((char *)&symkey, ptext + sizeof(int) + sizeof(short), sizeof(aes_data));
    
    printf("Got my symmetric key: %s\n", (char *)symkey.aes_key);
    
    // create encryption and decryption contexts
    EVP_CIPHER_CTX en_sym;
    EVP_CIPHER_CTX de_sym;
    if (aes_init(&en_sym, &de_sym, symkey)) {
        error("Couldn't initialize AES contexts\n");
    }
    
    // write back a verification message
    if (n < 0) {
        error("ERROR reading from socket");
    }
    else {
        // prepare the message by awkward way of unsigned char *
        string response_str = "Successfully established path.";
        int m = response_str.size() + 1;
        unsigned char response[m];
        response[m-1] = '\0';
        strcpy((char *)response, response_str.c_str());
            
        // encrypt buffer
        EVP_CIPHER_CTX_init(&en_sym);
    
        EVP_EncryptInit_ex(&en_sym, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       symkey.aes_key, symkey.aes_iv);
        printf("\nAbout to encrypt %d byte response: %s\n", m, response);
        unsigned char *ctext = aes_encrypt(&en_sym, response, &m);
        EVP_CIPHER_CTX_cleanup(&en_sym);
            
        // write out encrypted response
        write(sock, ctext, m);
    } 

    // infinite loop to receive requests
    while (1) {
        // zero the buffer
        bzero(buffer,bufferSize);
        
        // get a command string
        char command[bufferSize];
        bzero(command, bufferSize);
        
        // read the buffer in
        n = read(sock, buffer, bufferSize);
        if (n < 0) {
            error("ERROR reading from socket");
        }
        
        // decrypt buffer
        EVP_CIPHER_CTX_init(&de_sym);
    
        EVP_DecryptInit_ex(&de_sym, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       symkey.aes_key, symkey.aes_iv);
        printf("About to decrypt %d bytes: %s\n", n, buffer);
        unsigned char *ptext = aes_decrypt(&de_sym, buffer, &n);
        
        // convert the unsigned char we read in to a printable format        
        char site[n];
        strcpy(site, (char *)ptext);
        site[n-1] = '\0';
        
        // print ping request
        printf("Received ping request of %d bytes: %s\n\n", n, site);
        EVP_CIPHER_CTX_cleanup(&de_sym);
 
        // print to the command using the ping syntax and the site specified
        // in the buffer
        
        n = sprintf(command, "ping -c 1 %s", site);
        
        // give the command
        printf("command of %d bytes: %s\n", strlen(command), command);
        printf("buffer: %s\n", site);
        system(command);
        
        // send a reply about the command
        if (n < 0) {
            // prepare the message by awkward way of unsigned char *
            string response_str = "Server unavailable.";
            int m = response_str.size() + 1;
            unsigned char response[m];
            response[m-1] = '\0';
            strcpy((char *)response, response_str.c_str());
            
            // encrypt buffer
            EVP_CIPHER_CTX_init(&en_sym);
    
            EVP_EncryptInit_ex(&en_sym, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       symkey.aes_key, symkey.aes_iv);
            printf("About to encrypt %d bytes: %s\n", m, response);
            unsigned char *ctext = aes_encrypt(&en_sym, response, &m);
            printf("Relaying response of %d bytes: %s\n", m, (char *)ctext);
            EVP_CIPHER_CTX_cleanup(&en_sym);
            
            // write out encrypted response
            write(sock, ctext, m);
        }
        else {
            // prepare the message by awkward way of unsigned char *
            string response_str = "Ping successful.";
            int m = response_str.size() + 1;
            unsigned char response[m];
            response[m-1] = '\0';
            strcpy((char *)response, response_str.c_str());
            
            // encrypt buffer
            EVP_CIPHER_CTX_init(&en_sym);
    
            EVP_EncryptInit_ex(&en_sym, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       symkey.aes_key, symkey.aes_iv);
            printf("\nAbout to encrypt %d byte response: %s\n", m, response);
            unsigned char *ctext = aes_encrypt(&en_sym, response, &m);
            EVP_CIPHER_CTX_cleanup(&en_sym);
            
            // write out encrypted response
            write(sock, ctext, m);
        }
    }
}

int main(int argc, char *argv[])
{
    // sockets
    int sockfd, newsockfd, portno, pid;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    
    // args check
    if (argc < 2) {
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }
    
    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }
    
    bzero((char *)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("ERROR on binding");
    }
     
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    
    // infinite loop for receiving data
    while (1) {
        // get new socket
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            error("ERROR on accept");
        }
        
        // fork and do appropriate things
        pid = fork();
        if (pid < 0) {
            error("ERROR on fork");
        }
        
        if (pid == 0) {
            close(sockfd);
            dostuff(newsockfd);
            exit(0);
        }
        else {
            close(newsockfd);
        }
    }
    
    // done, close socket
    close(sockfd);
    return 0;
}

