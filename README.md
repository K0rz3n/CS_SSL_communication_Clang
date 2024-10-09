# Client-Server SSL communication in C language

## Description
This project mainly implements the SSL communication between Client and Server, using C language.

Specifically, it implements the following functions:

- Secure socket communication between client and server based on SSL
- Server side certificate verification using CA certificate in client side

Features:  

- SSL encryption based on OpenSSL 3.x library and TLSv1.3
- Strong cipher suite TLS_AES_256_GCM_SHA384 in TLSv1.3
- Customizing the certification path
- Customizing the IP address and port
- Prime error handling and annotation

## Project Structure
```
    ├── README.md
    ├── build
    │   ├── server.crt
    │   ├── server.key
    │   └── ca.crt
    ├── makefile
    ├── openssl_c
    │   ├── main.c
    │   ├── socket_c.c
    │   └── socket_c.h
    ├── openssl_s
        ├── main.c
        ├── socket_s.c
        └── socket_s.h
```

- build: Build directory
  - ca.crt: CA certificate to verify the server's certificate
  - server.crt: The certificate of the server
  - server.key: The private key of the server
- makefile: Makefile
- openssl_c: The folder of the client code
  - main.c: The entrance of the client code
  - socket_c.c: The code to build the socket connection
  - socket_c.h: Header file
- openssl_s: The folder of the server code
  - main.c: The entrance of the server code
  - socket_s.c: The code to build the socket connection
  - socket_c.h: Header file


## Dependencies
- System: Linux or MacOS
- Library: OpenSSL 3.x 

## Basic command

All the commands in this section are under the project folder.

### Build

The binary files of server and client code will be located in the folder ./build after running the following command.

```
make build
```
### Run

Address 0.0.0.0:port will be listening the connection after running the [run server] command.

SSL connection will be established after running the [run client] command


```
[run server] 
cd build 
./server --key/-k <server.key path> --crt/-c <server.crt path> --port/-p <listening port>

[run client]
cd build
./client --crt/-c <ca.crt path> --dst/-d <target ipv4 address> --port/-p <target port>
```

For example

```
[run server] 
cd build 
./server -k server.key -c server.crt -p 4433

[run client]
cd build
./client -c ca.crt -d 127.0.0.1 -p 4433
```


### Build Clean
```
make clean
```

