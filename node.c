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
    int n;
    char buffer[256];
    
    bzero(buffer,256);
    n = read(prev,buffer,255);
    if (n < 0) error("ERROR reading from socket");

    // private_decrypt(&buffer);

    // Set up outgoing socket
    int next, portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char serv[9] = "localhost";

    portno = atoi("51718");
    next = socket(AF_INET, SOCK_STREAM, 0);
    if (next < 0) 
        error("ERROR opening socket");
    server = gethostbyname(serv);
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
    if (connect(next,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    // Pass on buffer to next to continue symmetric key setup
    n = write(next,buffer,strlen(buffer));
    if (n < 0) 
        error("ERROR writing to socket");

    // Fork process to handle concurrent reading from both prev and next
    int pid = fork();
    if (pid < 0)
         error("ERROR on fork");

    while (1) {
	if (pid == 0)  {
            // Get response from next
            bzero(buffer,256);
            n = read(next,buffer,255);
            if (n < 0) 
                error("ERROR reading from socket");
            printf("Node received from next: %s\n",buffer);

            // Relay to prev
            n = write(prev,"I talked to next",16);
            if (n < 0) error("ERROR writing to socket");
        }
	else {
            // Get response from prev
            bzero(buffer,256);
            n = read(prev,buffer,255);
            if (n < 0) 
                error("ERROR reading from socket");
            printf("Node received from prev: %s\n",buffer);

            // Relay to next
            n = write(next,buffer,strlen(buffer));
            if (n < 0) error("ERROR writing to socket");
        }
    }
}
