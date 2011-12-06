/*
   CS 181a Final Project - Onion Router Server
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

void dostuff(int); /* function prototype */

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

/******** DOSTUFF() *********************
 There is a separate instance of this function 
 for each connection.  It handles all communication
 once a connnection has been established.
 *****************************************/
void dostuff(int sock)
{
    // get buffer and whatnot
    int bufferSize = 512;
    unsigned char buffer[bufferSize];
    bzero(buffer, bufferSize);
    
    // read in the data
    int n = 0;
    n = read(sock, buffer, bufferSize);
    
    // write back a verification message
    if (n < 0) {
        error("ERROR reading from socket");
    }
    else {
        write(sock,"Successfully established path.", 30); 
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
        
        // print to the command using the ping syntax and the site specified
        // in the buffer
        n = sprintf(command, "ping -c 1 %s", (char *)buffer);
        
        // give the command
        printf("command of %d bytes: %s\n", strlen(command), command);
        printf("buffer: %s\n", buffer);
        system(command);
        
        // send a reply about the command
        if (n < 0) {
            write(sock, "Server unavailable.\0", 20);
        }
        else {
            write(sock, "Ping successful.\0", 17);
        }
    }
}
