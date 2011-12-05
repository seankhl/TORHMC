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

////////////////////////////////////////////////////////////////

void newpath(int); /* Function to handle new connection through this node */

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
     int sockfd, newsockfd, portno, pid;
     socklen_t clilen;
     struct sockaddr_in serv_addr, cli_addr;

     if (argc < 2) {
         fprintf(stderr,"ERROR, no port provided\n");
         exit(1);
     }
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
        error("ERROR opening socket");
     bzero((char *) &serv_addr, sizeof(serv_addr));
     portno = atoi(argv[1]);
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(portno);
     if (bind(sockfd, (struct sockaddr *) &serv_addr,
              sizeof(serv_addr)) < 0) 
              error("ERROR on binding");
     listen(sockfd,5);
     clilen = sizeof(cli_addr);

     while (1) { // Loop indefinitely, spawning new processes to handle each path
         newsockfd = accept(sockfd, 
               (struct sockaddr *) &cli_addr, &clilen);
         if (newsockfd < 0) 
             error("ERROR on accept");

         pid = fork(); // Note: we are not dealing with zombies
         if (pid < 0)
             error("ERROR on fork");
         if (pid == 0)  {
             close(sockfd);
             newpath(newsockfd); // Handle new connection in new process
             exit(0);
         }
         else close(newsockfd);
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

/* newpath(int prev) -
   This function handles the creation of a new path through this node. Its input
   represents the socket connection leading 'into' this node along the path, and it
   establishes another socket connection leading 'out of' this node to facilitate
   the relaying of information. Upon creation, it is assumed that the first message
   received is encrypted with this node's public key, and decrypting it reveals
   the address of where to set up the outgoing connection, the symmetric key to use in
   this connection going forward, and the (still encrypted) payload to relay there.
*/
void newpath (int prev)
{
    int n, next;
    unsigned short portno = 0;
    int bufferSize = 512;
    int layerSize = 128;
    char buffer[bufferSize];
    struct sockaddr_in serv_addr;
    struct hostent *server;
    
    bzero(buffer,bufferSize);
    n = read(prev,buffer,bufferSize);
    if (n < 0) error("ERROR reading from socket");

    // Read in our layer
    unsigned char layer[layerSize];
    bzero(layer, layerSize);
    memcpy(layer, buffer, layerSize);

    // Now decrypt our layer with our private key
    EVP_PKEY *priv = read_privkey("privkey.pem");
    EVP_PKEY_CTX *de_ctx;
    ENGINE *f = ENGINE_get_default_RSA();
    ENGINE_init(f);
    de_ctx = EVP_PKEY_CTX_new(priv, f);

    size_t len = layerSize;
    unsigned char *ptext = rsa_decrypt(de_ctx, layer, len);

    next = socket(AF_INET, SOCK_STREAM, 0);
    if (next < 0) 
        error("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;

    int ipint;
    memcpy((char *) &ipint, ptext, 4);
    char * ip = intToIp(ipint);

    server = gethostbyname(ip);
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);

    memcpy((char *) &portno, ptext + 4, 2);
    printf("port: %d\n", portno);
    serv_addr.sin_port = htons(portno);

    if (connect(next,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    // Shift off user layer
    memmove(buffer, buffer + layerSize, bufferSize - layerSize);

    // Pass on buffer to next to continue symmetric key setup
    n = write(next,buffer,bufferSize);
    if (n < 0) 
        error("ERROR writing to socket");

    // Fork process to handle concurrent reading from both prev and next
    int pid = fork();
    if (pid < 0)
         error("ERROR on fork");

    while (1) {
	if (pid == 0)  {
            // Get response from next
            bzero(buffer,bufferSize);
            n = read(next,buffer,bufferSize); //used to be 255
            if (n < 0) 
                error("ERROR reading from socket");
            printf("Node received from next: %s\n",buffer);

            // Relay to prev
            n = write(prev,buffer,bufferSize); // used to be 255
            if (n < 0) error("ERROR writing to socket");
        }
	else {
            // Get response from prev
            bzero(buffer,bufferSize);
            n = read(prev,buffer,bufferSize); // used to be 255
            if (n < 0) 
                error("ERROR reading from socket");
            printf("Relaying ping request for: %s\n",buffer);

            // Relay to next
            n = write(next,buffer,strlen(buffer));
            if (n < 0) error("ERROR writing to socket");
        }
    }
}
