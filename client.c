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

int write_pubkey(RSA *key, char *filepath)
{
    BIO *pubkey_bio = BIO_new_file(filepath, "w");
    BIO_set_mem_eof_return(pubkey_bio, 0);
    PEM_write_bio_RSAPublicKey(pubkey_bio, key);
    BIO_free(pubkey_bio);
    return 0;
}

EVP_PKEY *read_pubkey(char *filepath)
{
    RSA *pubkey = RSA_new();
    BIO *pubkey_bio = BIO_new_file(filepath, "r");
    PEM_read_bio_RSAPublicKey(pubkey_bio, &pubkey, 0, NULL);
    BIO_free(pubkey_bio);
    
    EVP_PKEY *pubkey_evp = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubkey_evp, pubkey);
    return pubkey_evp;
}

int write_privkey(RSA *key, char *filepath)
{
    BIO *privkey_bio = BIO_new_file(filepath, "w");
    BIO_set_mem_eof_return(privkey_bio, 0);
    PEM_write_bio_RSAPrivateKey(privkey_bio, key, NULL, NULL, 0, 0, NULL);
    BIO_free(privkey_bio);
    return 0;
}

EVP_PKEY *read_privkey(char *filepath)
{
    RSA *privkey = RSA_new();
    BIO *privkey_bio = BIO_new_file(filepath, "r");
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

int ipToInt(char *ip)
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

int main(int argc, char *argv[])
{
    // sockets
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    // some consts for us
    const int bufferSize = 512;
    const int numNodes = 2;
    const int layerSize = 128;
    
    // args check
    if (argc < 3) {
       fprintf(stderr,"usage: %s hostname port\n", argv[0]);
       exit(0);
    }
    
    // get portno
    portno = atoi(argv[2]);
    
    // get socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }
    
    // get server
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    
    // set up sockets structs
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(portno);
    
    // connect to server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("ERROR connecting");
    }

    // our buffer
    unsigned char buffer[bufferSize];
    bzero(buffer, bufferSize);

    printf("Randomly selecting path...");
    
    // SIMPLFICIATION: path isn't "truly" random
    char *ips[2]      = {"127.0.0.1", "127.0.0.1"};
    char *keypaths[2] = {"keys/pubkey2.pem", "keys/pubkey2.pem"};
    short ports[2]    = {51716, 51718};

    // set up symmetric keys and encryption/decryption contexts
    aes_data symkeys[numNodes];
    EVP_CIPHER_CTX en_sym[numNodes];
    EVP_CIPHER_CTX de_sym[numNodes];
    
    int i = 0;
    for(i = 0; i < numNodes; i++) {
        symkeys[i] = aes_create();
        if (aes_init(&(en_sym[i]), &(de_sym[i]), symkeys[i])) {
            printf("Couldn't initialize AES System\n");
            exit(0);
        }
    }
    
    printf("DONE!\n");
    printf("Creating onion...");

    // go in REVERSE order so we can encrypt naturally
    for (i = numNodes - 1; i >= 0; i--) {
        // set up the layer
        unsigned char layer[layerSize];
        bzero(layer, layerSize);

        // get the IP number, port, and symmetric key for this layer
        int ipint = ipToInt(ips[i]);
        short portshort = ports[i];
        aes_data symkey = symkeys[i];

        // copy them into the layer
        memcpy(layer,                               (char *)&ipint,     sizeof(int));
        memcpy(layer + sizeof(int),                 (char *)&portshort, sizeof(short));
        memcpy(layer + sizeof(int) + sizeof(short), (char *)&symkey,    sizeof(aes_data));
        
        // set up RSA engine
        ENGINE *e = ENGINE_get_default_RSA();
        ENGINE_init(e);
        
        // read in the public key and set up a context with it
        EVP_PKEY *pub = read_pubkey(keypaths[i]);
        EVP_PKEY_CTX *en_ctx;
        en_ctx = EVP_PKEY_CTX_new(pub, e);
        
        // our layers have an 86-byte plantext maximum for a 128-byte encrypted size
        size_t len = 86;
        
        // encrypt the layer; modifies len to be length of ctext
        unsigned char *ctext = rsa_encrypt(en_ctx, layer, len);
        
        if (len == layerSize) {
            // if it worked, copy into the buffer
            memcpy(buffer + i*layerSize, ctext, layerSize);
        }
        else {
            printf("everything is fucked!: %d\n", len);
            exit(0);
        }
        
        // free the context for the next one
        EVP_PKEY_CTX_free(en_ctx);
    }
    
    printf("DONE!\nEstablishing symmetric encryption through the path...");
    
    // write out the buffer to the next node so it can get its stuff
    n = write(sockfd, buffer, bufferSize);
    if (n < 0) {
        error("ERROR writing to socket");
    }

    // zero out our buffer so we can start passing messages
    bzero(buffer, bufferSize);
    
    // get a response
    n = read(sockfd, buffer, bufferSize);

    printf("DONE!\nGot response from exit node.\nAnonymous network connection established. ", buffer);

    // infinite loop for pinging sites
    while (1) {
        printf("Who do you want to ping? ");
        // construct our message
        unsigned char message[bufferSize];
        bzero(message, bufferSize);
        
        // ask for a site from stdin
        fgets((char *)message, 255, stdin);

        // encrypt buffer with symmetric keys in FORWARD order
        // NOTE: adds ~16 bytes per layer
        int len = strlen((char *)message);
        for (i = numNodes - 1; i >= 0; i--) {
            // encrypt message
            EVP_CIPHER_CTX_init(&(en_sym[i]));
    
            EVP_EncryptInit_ex(&(en_sym[i]), 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       symkeys[i].aes_key, symkeys[i].aes_iv);

            unsigned char *ctext = aes_encrypt(&(en_sym[i]), message, &len);
            
            // copy message from ctext back to message so we can keep going
            memcpy(message, ctext, len);

            EVP_CIPHER_CTX_cleanup(&(en_sym[i]));
        }

        // relay down the path
        n = write(sockfd,message,len);
        if (n < 0) {
             error("ERROR writing to socket");
        }
        
        // zero out the buffer (we just sent it)
        bzero(message, bufferSize);

        // wait for response
        n = read(sockfd, message, bufferSize);
        if (n < 0) {
            error("ERROR reading from socket");
        }
        
        // decrypt buffer with symmetric keys in reverse order
        len = n;
        unsigned char *ptext;
        for (i = 0; i < numNodes; i++) {
            // encrypt message
            EVP_CIPHER_CTX_init(&(de_sym[i]));
    
            EVP_DecryptInit_ex(&(de_sym[i]), 
                       EVP_aes_256_cbc(), 
                       NULL, 
                       symkeys[i].aes_key, symkeys[i].aes_iv);

            ptext = aes_decrypt(&(de_sym[i]), message, &len);
            
            // copy message from ctext back to message so we can keep going
            memcpy(message, ptext, len);
            
            printf("decrypted size: %d bytes\n", len);

            EVP_CIPHER_CTX_cleanup(&(de_sym[i]));
        }
        char serverResponse[len];
        bzero(serverResponse, len);
        n = sprintf(serverResponse, "%s", (char *)ptext);
        for (int z = 0; z < len; ++z) {
            printf("%c ", serverResponse[z]);
        }
        
        printf("\nResponse of %d bytes from server: %s\n", strlen(serverResponse), serverResponse);
    }
    
    // done, close socket
    close(sockfd);
    return 0;
}
