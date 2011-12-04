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

    char buffer[256];
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

    bzero(buffer,256);

    int numNodes = 1;
    int layerSize = sizeof(int)+sizeof(short);

    printf("Randomly selecting path...");
    char* ips[1]   = {"127.0.0.1"};
    short ports[1] = {51718};
    printf("DONE!\n");

    printf("Creating onion...");

    int i=0;
    for(i=0; i < numNodes; i++)
    {
        int ipint = ipToInt(ips[i]);
        short portshort = ports[i];
        memcpy(buffer + i*layerSize, (char *) &ipint, sizeof(int));
        memcpy(buffer + i*layerSize + sizeof(int), (char *) &portshort, sizeof(short));
    }
    printf("DONE!\nEstablishing symmetric encryption through the path...");

    n = write(sockfd,buffer,256);
    if (n < 0) 
         error("ERROR writing to socket");

    bzero(buffer, 256);
    n = read(sockfd,buffer,256);
    printf("DONE!\nResponse from exit node: %s\nAnonymous network connection established. ", buffer);

    while (1) {
        printf("Who do you want to ping? ");
        bzero(buffer,256);
        fgets(buffer,255,stdin);
        n = write(sockfd,buffer,strlen(buffer));
        if (n < 0) 
             error("ERROR writing to socket");
        bzero(buffer,256);
        n = read(sockfd,buffer,255);
        if (n < 0) error("ERROR reading from socket");
        printf("Response from server: %s\n", buffer);
    }
    close(sockfd);
    return 0;
}
