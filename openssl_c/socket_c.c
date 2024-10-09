//
//  socket_c.c
//  openssl_c
//
//  Created by K0rz3n on 05/10/2024.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "socket_c.h"

#define BUFFER_SIZE 1024

int connectSocket(char* ip_str ,int port){
    int sock_cli = 0;
    struct sockaddr_in serv_addr;

    
    // create socket
    if ((sock_cli = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // convert ip_str to binary format
    if (inet_pton(AF_INET, ip_str, &serv_addr.sin_addr) <= 0) {
        printf("Invalid address/ Address not supported\n");
        close(sock_cli);
        return -1;
    }
    
    // create connect to server address
    if(connect(sock_cli, (struct sockaddr*)&serv_addr, sizeof(serv_addr))<0){
        printf("Connection failed\n");
        close(sock_cli);
        return -1;
    }
    printf("Socket connected to %s:%d\n",ip_str, port);
    return sock_cli;
}
