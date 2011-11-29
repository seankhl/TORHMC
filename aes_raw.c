#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <assert.h>
#include <iostream>
#include <sys/time.h>

using namespace std;

unsigned char *randStr(unsigned char *str, int len, bool newseed=false)
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

int main(int argc, char *argv[])
{
    unsigned char testIn[1024];
    randStr(testIn, 1024, true);

    unsigned char testOut[1024];
    unsigned char testFin[1024];

    unsigned char iv[16], eiv[16], div[16], key32[32];
    RAND_bytes(key32,  sizeof(key32));
    RAND_bytes(iv,     sizeof(iv));
    
    AES_KEY ekey, dkey;
	AES_set_encrypt_key(key32, 256, &ekey);
	AES_set_decrypt_key(key32, 256, &dkey);

    memcpy(iv, eiv, 16);
    memcpy(iv, div, 16);

    AES_cbc_encrypt(testIn,  testOut, 1024, &ekey, eiv, AES_ENCRYPT);
    AES_cbc_encrypt(testOut, testFin, 1024, &dkey, div, AES_DECRYPT);
    
    for (int i = 0; i < 1024; ++i) {
        cout << testIn[i] << testFin[i] << endl;
    }

    string printIn((char *)testIn, 1024);
    string printOut((char *)testOut, 1024);
    string printFin((char *)testFin, 1024);

    cout << printIn << endl;
    cout << "" << endl;
    cout << printOut << endl;
    cout << "" << endl;
    cout << printFin << endl;

    assert(memcmp(testIn, testFin, 1024) == 0);

    return 0;
}
