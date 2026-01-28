#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define DEFAULT_LOCAL_PORT 8443
#define DEFAULT_REMOTE_HOST "127.0.0.1"
#define DEFAULT_REMOTE_PORT 5001

static int local_port = DEFAULT_LOCAL_PORT;
static char remote_host[256] = DEFAULT_REMOTE_HOST;
static int remote_port = DEFAULT_REMOTE_PORT;

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);
void url_decode(const char *src, char *dst, size_t dst_size);

// TODO: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "b:r:p:")) != -1) {
        switch (opt) {
            case 'b':
                local_port = atoi(optarg);
                if (local_port <= 0) {
                    fprintf(stderr, "Invalid local port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'r':
                snprintf(remote_host, sizeof(remote_host), "%s", optarg);
                break;
            case 'p':
                remote_port = atoi(optarg);
                if (remote_port <= 0) {
                    fprintf(stderr, "Invalid remote port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                fprintf(stderr, "Usage: %s [-b port] [-r host] [-p port]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);
    //implements openssl initialization
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        fprintf(stderr, "Error: OpenSSL initialization failed\n");
        exit(EXIT_FAILURE);
    }
    //sets up ssl context
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Error: SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Error: Failed to load certificate file\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Error: Failed to load private key file\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(local_port);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (listen(server_socket, 10) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", local_port);

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        //implement create ssl structure and make handshake
        SSL *ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            continue;
        }

        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        
        if (ssl != NULL) {
            handle_request(ssl);
        }
        //shut down ssl connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        
        close(client_socket);
    }

    close(server_socket);
    //shut down ssl context
    if (ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
    }
    
    return 0;
}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    char decoded_path[BUFFER_SIZE];
    ssize_t bytes_read;

    bytes_read = 0;
    bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    
    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1);
    strcpy(request, buffer);
    
    char *method = strtok(request, " ");
    char *file_name = strtok(NULL, " ");
    if (file_name == NULL) {
        free(request);
        return;
    } 
    if(file_name[0] == '/'){
        file_name = file_name + 1;
    }
    
    url_decode(file_name, decoded_path, sizeof(decoded_path));
    file_name = decoded_path;

    char *http_version = strtok(NULL, " ");
    printf("DEBUG: file_name %s\n", file_name);
    if (file_exists(file_name)) {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
    free(request);
}
//helps the server not struggle with spaces or percents in a url. If it sees a %, it'll 
//try to treat the % and next 2 chars as hex byte. else, copy as-is
void url_decode(const char *src, char *dst, size_t dst_size) {
    size_t di = 0;
    for (size_t si = 0; src[si] != '\0' && di + 1 < dst_size; ++si) {
        if (src[si] == '%' && src[si + 1] != '\0' && src[si + 2] != '\0') {
            char hex[3];
            hex[0] = src[si + 1];
            hex[1] = src[si + 2];
            hex[2] = '\0';
            char *end = NULL;
            long val = strtol(hex, &end, 16);
            if (end != NULL && *end == '\0') {
                dst[di++] = (char)val;
                si += 2;
                continue;
            }
        }
        dst[di++] = src[si];
    }
    dst[di] = '\0';
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";
        SSL_write(ssl, response, (int)strlen(response));
        
        return;
    }

    char *response;
    if (strstr(path, ".html")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    } else if (strstr(path, ".txt")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    } else if (strstr(path, ".jpg")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: image/jpeg\r\n\r\n";
    } else if (strstr(path, ".m3u8")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/vnd.apple.mpegurl\r\n\r\n";
    } else if (!strchr(path, '.')) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/octet-stream\r\n\r\n";
    } else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    }

    SSL_write(ssl, response, (int)strlen(response));
    

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SSL_write(ssl, buffer, (int)bytes_read);
        
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, remote_host, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(remote_port);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // TODO: Forward response to client via SSL
        SSL_write(ssl, buffer, (int)bytes_read);
        
    }

    close(remote_socket);
}
