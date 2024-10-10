#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "socket_c.h"

#define BUFFER_SIZE 1024
#define CIPHER_SUITE "TLS_AES_256_GCM_SHA384"

// ssl initialization
void init_openssl(void) {
    OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// ssl recycling
void cleanup_openssl(void) {
    EVP_cleanup();
}

// unified resources recycling
void cleanup_resources(SSL *ssl, int real_socket, SSL_CTX *ctx, char *line) {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (real_socket != -1) {
        close(real_socket);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    if (line) {
        free(line);
    }
    cleanup_openssl();
}

// gain ssl status
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


// create SSL context
SSL_CTX *create_client_context(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;
    // client method
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// choose the cipher suite
void cipher_suite_choose(SSL_CTX *ctx, char* cipher_suite){
    if (SSL_CTX_set_ciphersuites(ctx, cipher_suite) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// configure context to load certificate and set verify
void configure_client_context(SSL_CTX *ctx, char* cert_addr) {
    // load CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, cert_addr, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // verify server certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // choose cipher suite
    cipher_suite_choose(ctx, CIPHER_SUITE);
}

// resolve parameters
int getargs(int argc, char **argv, char **crt_value, char** dst_value, int* port_value){
    
    int opt;
    int crt_option = 0;
    int dst_option = 0;
    int port_option = 0;
    char *endptr = NULL;
    
   
    struct option long_options[] = {
        {"crt", required_argument, 0, 'c'},
        {"dst", required_argument, 0, 'd'},
        {"port", required_argument, 0, 'p'},
        // end signal
        {0, 0, 0, 0}
    };

    
    while ((opt = getopt_long(argc, argv, "c:d:p:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                crt_option = 1;
                *crt_value = optarg;
                break;
            case 'd':
                dst_option = 1;
                *dst_value = optarg;
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
    
    if(crt_option+dst_option+port_option != 3){
        printf("Miss some options:\n");
        if(crt_option == 0){
            printf("--crt/-c <CA certificate file path>\n");
        }
        if(dst_option == 0){
            printf("--dst/-d <target server address>\n");
        }
        if(port_option == 0){
            printf("--port/-p <target server port>\n");
        }
        return 1;
    }

    return 0;
}

int main(int argc, char** argv) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int real_socket = -1;
    char* line = NULL;
    size_t len = 0;
    ssize_t read_line;
    char buffer[BUFFER_SIZE] = {0};
    char* crt_value = NULL;
    char* dst_value = NULL;
    int port_value = 0;
    int args_check = 0;
    
    // argument receive and check
    args_check = getargs(argc, argv, &crt_value, &dst_value, &port_value);
    if(args_check == 1){
        exit(EXIT_FAILURE);
    }

    // init and configure
    init_openssl();
    ctx = create_client_context();
    configure_client_context(ctx,crt_value);
    
    // SSL callback
    SSL_CTX_set_info_callback(ctx, ssl_info_callback);
    
    
    // create socket connection
    if((real_socket = connectSocket(dst_value, port_value)) == -1){
        ERR_print_errors_fp(stderr);
        cleanup_resources(ssl, real_socket, ctx, line);
        exit(EXIT_FAILURE);
    }
    
    // create SSL session
    if((ssl = SSL_new(ctx)) == NULL){
        ERR_print_errors_fp(stderr);
        cleanup_resources(ssl, real_socket, ctx, line);
        exit(EXIT_FAILURE);
    }
    
    // bind socket to SSL
    if(SSL_set_fd(ssl, real_socket)<=0){
        ERR_print_errors_fp(stderr);
        cleanup_resources(ssl, real_socket, ctx, line);
        exit(EXIT_FAILURE);
    }

    // SSL handshake and connection
    if(SSL_connect(ssl) > 0){
        while ((read_line = getline(&line, &len, stdin)) !=-1) {
            //delete the last \n in the line
            size_t input_len = strlen(line);
            if (input_len > 1 && line[input_len - 1] == '\n') {
                line[input_len - 1] = '\0';
            }else if(input_len == 1 && line[0] == '\n'){
                continue;
            }
            // send message to server
            if(SSL_write(ssl, line, (int)strlen(line)) <0){
                printf("Message sent failed");
            }
            printf("Message of %d words sent to server: %s\n",(int)strlen(line), line);
    
            // accept message from server to check whether message has been received or not
            memset(buffer, 0, BUFFER_SIZE);
            if (SSL_read(ssl, buffer, BUFFER_SIZE) == 0) {
                printf("Server disconnected\n");
                break;
            }
            printf("Acknowledge message received from server: %s\n", buffer);
        }
    
    }else{
        ERR_print_errors_fp(stderr);
        cleanup_resources(ssl, real_socket, ctx, line);
        exit(EXIT_FAILURE);
    }
    cleanup_resources(ssl, real_socket, ctx, line);
    return 0;
}
