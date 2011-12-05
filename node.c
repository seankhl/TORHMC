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

/////////////////////////////////////////////////////////////////
/* Node functions                                              */
/////////////////////////////////////////////////////////////////

void newpath(int); /* Function to handle new connection through this node */

void error(const char *msg)
{
    perror(msg);
    exit(1);
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
    
    // set up connection
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }
        
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("ERROR on binding");
    }
    
    listen(sockfd,5);
    clilen = sizeof(cli_addr);

    // loop indefinitely, spawning new processes to handle each path
    while (1) { 
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            error("ERROR on accept");
        }
        
        // NOTE: we are not dealing with zombies
        pid = fork();
        if (pid < 0) {
            error("ERROR on fork");
        }
        
        if (pid == 0) {
            close(sockfd);
            // handle new connection in new process
            newpath(newsockfd);
            exit(0);
        }
        else {
            close(newsockfd);
        }
    }
    close(sockfd);
    return 0;
}

int ipToInt(char * ip)
{
    int a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    return ((a & 0xFF) << 24) + ((b & 0xFF) << 16) + ((c & 0xFF) << 8) + (d & 0xFF);
}

char *intToIp(int i)
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

/* newpath(int prev) -
   This function handles the creation of a new path through this node. Its input
   represents the socket connection leading 'into' this node along the path, and it
   establishes another socket connection leading 'out of' this node to facilitate
   the relaying of information. Upon creation, it is assumed that the first message
   received is encrypted with this node's public key, and decrypting it reveals
   the address of where to set up the outgoing connection, the symmetric key to use in
   this connection going forward, and the (still encrypted) payload to relay there.
*/
void newpath(int prev)
{
    // some vars
    int n, next, pid;
    unsigned short portno = 0;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    
    // some consts for us
    int bufferSize = 512;
    int layerSize = 128;
    
    // set up the buffer
    unsigned char buffer[bufferSize];
    bzero(buffer, bufferSize);
    n = read(prev, buffer, bufferSize);
    if (n < 0) {
        error("ERROR reading from socket");
    }
    
    // get the socket to the next node
    next = socket(AF_INET, SOCK_STREAM, 0);
    if (next < 0) {
        error("ERROR opening socket");
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;

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

    // extract our IP for the next node connection
    int ipint;
    memcpy((char *)&ipint, ptext, sizeof(int));
    char *ip = intToIp(ipint);
    server = gethostbyname(ip);
    bcopy((char *)server->h_addr, 
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);

    // extract our port for next node connection
    memcpy((char *)&portno, ptext + sizeof(int), sizeof(short));
    printf("port: %u\n", portno);
    serv_addr.sin_port = htons(portno);

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

    // connect to next node
    if (connect(next, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("ERROR connecting");
    }

    // shift off used layer to relay rest of onion
    memmove(buffer, buffer + layerSize, bufferSize - layerSize);

    // pass on buffer to next to continue symmetric key setup
    n = write(next, buffer, bufferSize);
    if (n < 0) {
        error("ERROR writing to socket");
    }
    
    // fork process to handle concurrent reading from both prev and next
    pid = fork();
    if (pid < 0) {
        error("ERROR on fork");
    }
    
    // now that symmetric keys have been established, we simply listen on both
    // ends of the connection and encrypt or decrypt and relay as appropriate
    while (1) {
        // coming back from server
        if (pid == 0)  {
            int m = 0;
            unsigned char message[bufferSize];
            // get response from next
            bzero(message, bufferSize);
            m = read(next, message, bufferSize);
            if (m < 0) {
                error("ERROR reading from socket");
            }
            
            printf("Message received from next: %s\n", message);

            // encrypt buffer
            //unsigned char *ctext = aes_encrypt(&en_sym, message, &n);
            EVP_CIPHER_CTX_init(&en_sym);
    
            EVP_EncryptInit_ex(&en_sym, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       symkey.aes_key, symkey.aes_iv);
            printf("About to encrypt %d bytes: %s\n", m, message);
            unsigned char *ctext = aes_encrypt(&en_sym, message, &m);
            printf("Relaying ping request of %d bytes: %s\n", m, (char *)ctext);
            EVP_CIPHER_CTX_cleanup(&en_sym);

            // relay to prev
            m = write(prev, ctext, m);
            if (m < 0) {
                error("ERROR writing to socket");
            }
        }
        // going towards server
        else {
            int m = 0;
            // get response from prev
            unsigned char message[bufferSize];
            bzero(message, bufferSize);
            m = read(prev, message, bufferSize);
            if (m < 0) {
                error("ERROR reading from socket");
            }
            
            // decrypt buffer
            EVP_CIPHER_CTX_init(&de_sym);
    
            EVP_DecryptInit_ex(&de_sym, 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       symkey.aes_key, symkey.aes_iv);
            printf("About to decrypt %d bytes: %s\n", n, message);
            unsigned char *ptext = aes_decrypt(&de_sym, message, &m);
            printf("Relaying ping request of %d bytes: %s\n", m, (char *)ptext);
            EVP_CIPHER_CTX_cleanup(&de_sym);

            // relay to next
            m = write(next, ptext, m);
            if (m < 0) {
                error("ERROR writing to socket");
            }
        }
    }
}
