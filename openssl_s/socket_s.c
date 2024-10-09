//
//  socket_s.c
//  openssl_c
//
//  Created by K0rz3n on 05/10/2024.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "socket_s.h"

#define INITIAL_BUFFER_SIZE 1024


int createSocket(int port){
    int server_fd;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    
    //create a socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        return -1;
    }
    
    // set address and post
    address.sin_family = AF_INET; // IPv4
    address.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
    address.sin_port = htons(port); // host to network short
    
    // bind address and port to the socket
    if (bind(server_fd, (struct sockaddr *)&address, addr_len) < 0) {
        perror("Bind failed");
        close(server_fd);
        return -1;
    }
    
    // start listening
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        return -1;
    }
    
    return server_fd;
    
}























