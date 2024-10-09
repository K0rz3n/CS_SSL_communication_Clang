#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "socket_s.h"

#define INITIAL_BUFFER_SIZE 1024

void init_openssl(void) {
    OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl(void) {
    EVP_cleanup();
}




void cleanup_resources(SSL *ssl, int server_fd, int real_socket,  char *buffer, SSL_CTX *ctx) {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (server_fd >= 0) {
        close(server_fd);
    }
    if (real_socket >= 0) {
        close(real_socket);
    }
    if (buffer) {
        free(buffer);
    }
   
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    cleanup_openssl();
}


void ssl_info_callback(const SSL *ssl, int where, int ret)
{
    const char *str = NULL;
    int w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP)
        printf("> SSL-STATE->%s: %s\n", str, SSL_state_string_long(ssl));
    else if (where & SSL_CB_ALERT)
    {
        str = (where & SSL_CB_READ) ? "read" : "write";
        printf("> SSL-ALERT: %s: %s: %s\n", str,
               SSL_alert_type_string_long(ret),
               SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT)
    {
        if (ret == 0)
            printf("> SSL-ERROR: %s: failed in %s\n", str, SSL_state_string_long(ssl));
        else if (ret < 0)
            printf("> SSL-ERROR: %s: error in %s\n", str, SSL_state_string_long(ssl));
    }
}



SSL_CTX *create_server_context(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;
    // server method
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_server_context(SSL_CTX *ctx, char* cert_addr, char* key_addr) {
    // load server side certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, cert_addr, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_addr, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
}

int getargs(int argc, char **argv, char **crt_value, char **key_value, int* port_value){
    
    int opt;
    int crt_option = 0;
    int key_option = 0;
    int port_option = 0;
    char *endptr = NULL;
    
   
    struct option long_options[] = {
        {"key", required_argument, 0, 'k'},
        {"crt", required_argument, 0, 'c'},
        {"port", required_argument, 0, 'p'},
        // end signal
        {0, 0, 0, 0}
    };


    while ((opt = getopt_long(argc, argv, "k:c:p:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'k':
                key_option = 1;
                *key_value = optarg;
                break;
            case 'c':
                crt_option = 1;
                *crt_value = optarg;
                break;
            case 'p':
                port_option = 1;
                *port_value = (int)strtol(optarg, &endptr, 10);
                break;
            case '?':
                printf("Unknown option.\n");
                return 1;
            case ':':
                printf("Option -%c requires an argument.\n", optopt);
                return 1;
        }
    }
    
    if(key_option+crt_option+port_option !=3){
        printf("Miss some options:\n");
        if(key_option == 0){
            printf("--key/-k <secret key file path>\n");
        }
        if(crt_option == 0){
            printf("--crt/-c <certificate file path>\n");
        }
        if(port_option == 0){
            printf("--port/-p <listening port>\n");
        }
        return 1;
    }

    return 0;
}



int main(int argc, char **argv) {
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    int real_socket = -1;
    char* buffer = NULL;
    size_t buffer_size = INITIAL_BUFFER_SIZE;
    size_t received_temp = 0;
    char* message = "Message has been received";
    char* crt_value = NULL;
    char* key_value = NULL;
    int port_value = 0;
    int server_fd = -1;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char client_ip[INET_ADDRSTRLEN];
    int args_check = 0;
    
    // argument check
    args_check = getargs(argc, argv, &crt_value, &key_value, &port_value);
    if (args_check == 1) {
        cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
        exit(EXIT_FAILURE);
    }
    
    // initialization
    init_openssl();
    // create SSL context
    ctx = create_server_context();
    if (!ctx) {
        cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
        exit(EXIT_FAILURE);
    }
    
    // configure the SSL context such as key
    configure_server_context(ctx, crt_value, key_value);
    printf("Certificate and private key loaded and verified\n");
    
    // get the socket connecting to the client
    if ((server_fd = createSocket(port_value)) == -1) {
        ERR_print_errors_fp(stderr);
        cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
        exit(EXIT_FAILURE);
    }

    // SSL callback
    SSL_CTX_set_info_callback(ctx, ssl_info_callback);
    
    // init buffer
    buffer = (char*) malloc(buffer_size);
    if (buffer == NULL) {
        perror("Malloc failed");
        cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
        exit(EXIT_FAILURE);
    }
    
    while (1) {
        
        printf("Waiting for a new connection at 0.0.0.0:%d\n",port_value);
        // accept the client connection
        if ((real_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
            perror("Accept failed");
            cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
            exit(EXIT_FAILURE);
        }
        
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);
        printf("New connection from: %s:%d\n", client_ip, client_port);
        
        // create new SSL object
        ssl = SSL_new(ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
            exit(EXIT_FAILURE);
        }
        
        // associate SSL object with socket
        if (SSL_set_fd(ssl, real_socket) <= 0) {
            ERR_print_errors_fp(stderr);
            cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
            exit(EXIT_FAILURE);
        }
        
        // SSL handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
            exit(EXIT_FAILURE);
        } else {
            // Handle communication
            size_t total_received = 0;
            
            while (1) {
                ssize_t received_size = SSL_read(ssl, buffer + total_received, (int)(buffer_size - total_received - 1));
                if (received_size < 0) {
                    printf("Recv failed\n");
                    break;
                } else if (received_size == 0) {
                    printf("Connection has closed\n");
                    break;
                }
                
                received_temp = total_received;
                total_received += received_size;
                buffer[total_received] = '\0';
                
                // Extend buffer if necessary
                if (total_received + 1 >= buffer_size) {
                    buffer_size *= 2;
                    char* new_buffer = realloc(buffer, buffer_size);
                    if (!new_buffer) {
                        printf("Realloc failed\n");
                        cleanup_resources(ssl, server_fd, real_socket, buffer, ctx);
                        exit(EXIT_FAILURE);
                    }
                    buffer = new_buffer;
                }
                
                // Send response
                if (SSL_write(ssl, message, (int)strlen(message)) < 0) {
                    printf("Acknowledge message sent failed\n");
                    break;
                }
                
                printf("\nMessage of %d words has beed received: %s\n",(int)received_size,buffer+received_temp);
                printf("Acknowledge message was sent to client\n");
            }
            // Close connection
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(real_socket);
            ssl = NULL;
            real_socket = -1;
    
        }
        
       
    }
    
}
    
    
