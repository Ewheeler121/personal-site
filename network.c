#include <alloca.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <regex.h>

#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "network.h"

handle_t *handlers = NULL;
SSL_CTX *serverctx = NULL;
int serverfd = 0, epollfd = 0;

void graceful_close(int sig) {
    SSL_CTX_free(serverctx);
    close(serverfd);
    close(epollfd);
    exit(EXIT_SUCCESS);
}

void set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE] = {0};
    //do stuff
    int bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE);
    if(bytes_read == 0) {
        //disconnected
        epoll_ctl(epollfd, EPOLL_CTL_DEL, SSL_get_fd(ssl), NULL);
        close(SSL_get_fd(ssl));
        SSL_free(ssl);
    } else if(bytes_read < 0) {
        //error, ignore this
        return;
    }

    //got response
    buffer[bytes_read] = '\0';
    char *head_end = strstr(buffer, " HTTP/1.1");
    if(head_end == NULL) {
        SSL_write(ssl, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", 48);
        return;
    }
    char *head = alloca((head_end - buffer) + 1);
    strncpy(head, buffer, (head_end - buffer));
    head[(head_end - buffer)] = '\0';
    
    regex_t reg;
    int i = 0;
    while(handlers[i].reg_match != NULL) {
        if(regcomp(&reg, handlers[i].reg_match, REG_EXTENDED)) {
            i++;
            continue;
        }
        if(!regexec(&reg, head, 0, NULL, 0)) {
            regfree(&reg);
            handlers[i].function (ssl, buffer);
            return;
        }
        regfree(&reg);
        i++;
    }

    //not found
    if(handlers[i].function != NULL) {
        handlers[i].function (ssl, buffer);
    } else {
        SSL_write(ssl, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 46);
    }
}

int server_init(handle_t *handles) {
    handlers = handles;
    //Socket
    struct sockaddr_in addr = {AF_INET, htons(PORT), {0}};

    if((serverfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("ERROR: could not create socket");
        return 1;
    }
    if(bind(serverfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("ERROR: could not create socket");
        return 1;
    }
    if(listen(serverfd, SOMAXCONN) < 0) {
        perror("ERROR: could not create socket");
        return 1;
    }
    set_nonblocking(serverfd);

    //SSL
    if((serverctx = SSL_CTX_new(TLS_server_method())) == NULL) {
        fputs("ERROR: could not create certificate", stderr);
        return 1;
    }
    if(SSL_CTX_use_PrivateKey_file(serverctx, PRIVATEKEY, SSL_FILETYPE_PEM) != 1) {
        fputs("ERROR: could not use Private Key", stderr);
        return 1;
    }
    if(SSL_CTX_use_certificate_chain_file(serverctx, CHAINFILE) != 1) {
        fputs("ERROR: could not use Chain File", stderr);
        return 1;
    }

    //epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = serverfd;

    if((epollfd = epoll_create1(0)) < 0) {
        perror("ERROR: could not create epoll");
        close(serverfd);
        return 1;
    }
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, serverfd, &ev) < 0) {
        perror("ERROR: could not create epoll");
        close(serverfd);
        return 1;
    }

    return 0;
}

void server_run() {
    char buffer[BUFFER_SIZE];
    struct epoll_event events[MAX_EVENTS];

    //signal
    if(signal(SIGINT, graceful_close) == SIG_ERR || signal(SIGTERM, graceful_close) == SIG_ERR) {
        perror("ERROR: could not set signal");
        close(serverfd);
        return;
    }

    while(1) {
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if(nfds < 0) {
            break;
        }

        for(int i = 0; i < nfds; i++) {
            int clientfd, eventfd = events[i].data.fd;
            //add clients
            if(eventfd == serverfd) {
                struct epoll_event ev;
                if((clientfd = accept(serverfd, NULL, 0)) < 0) {
                    perror("ERROR: accept failed");
                    continue;
                }
                set_nonblocking(clientfd);
                
                SSL *ssl = SSL_new(serverctx);
                SSL_set_fd(ssl, clientfd);
                ev.events = EPOLLIN | EPOLLET;
                ev.data.ptr = ssl;
                if(epoll_ctl(epollfd, EPOLL_CTL_ADD, clientfd, &ev) < 0) {
                    perror("ERROR: epoll control failed");
                    close(clientfd);
                }
            //handle clients
            } else {
                SSL *ssl = (SSL *)events[i].data.ptr;
                //handshake
                if(!SSL_is_init_finished(ssl)) {
                    int handshake_ret = SSL_accept(ssl);
                    if(handshake_ret <= 0) {
                        int err = SSL_get_error(ssl, handshake_ret);
                        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                            continue;
                        }
                        continue;
                    }
                }
                handle_client(ssl);
            }
        }
    }
}

int send_file(SSL *ssl, char *filename) {
    FILE *file;
    char *filetype;
    size_t s_filetype, s_file;

    if((file = fopen(filename, "rb")) == NULL) {
        SSL_write(ssl, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 45);
        return -1;
    }

    if((filetype = strrchr(filename, '.')) == NULL) {
        SSL_write(ssl, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 45);
        fclose(file);
        return -1;
    }
    filetype++;
    s_filetype = strlen(filetype);
    
    //text
    if(!strncmp("html", filetype, s_filetype) || !strncmp("htm", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n", 42);
    } else if(!strncmp("css", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n", 41);
    } else if(!strncmp("js", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n", 57);
    } else if(!strncmp("txt", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n", 43);
    //pictures
    } else if(!strncmp("gif", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\n", 42);
    } else if(!strncmp("svg", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\n", 46);
    } else if(!strncmp("webp", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: image/webp\r\n", 43);
    } else if(!strncmp("png", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n", 42);
    } else if(!strncmp("jpg", filetype, s_filetype) || !strncmp("jpeg", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n", 43);
    } else if(!strncmp("ico", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\n", 45);
    //videos
    } else if(!strncmp("mp4", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n", 42);
    } else if(!strncmp("webm", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: image/webm\r\n", 43);
    //application
    } else if(!strncmp("json", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n", 49);
    } else if(!strncmp("pdf", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n", 48);
    //fonts
    } else if(!strncmp("woff", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: font/woff\r\n", 42);
    } else if(!strncmp("woff2", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: font/woff2\r\n", 43);
    } else if(!strncmp("ttf", filetype, s_filetype)) {
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: font/ttf\r\n", 41);
    } else {
        SSL_write(ssl, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 45);
        return -1;
    }
    
    char buffer[BUFFER_SIZE];
    fseek(file, 0, SEEK_END);
    int length = ftell(file);
    rewind(file);
    snprintf(buffer, 40, "Content-Length: %i\r\n\r\n", length);
    SSL_write(ssl, buffer, strlen(buffer));

    while((s_file = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        SSL_write(ssl, buffer, BUFFER_SIZE);
    }

    fclose(file);
    return 0;
}
