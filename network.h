#ifndef NETWORK_H
#define NETWORK_H

#include <openssl/ssl.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 8192
#define MAX_EVENTS 10
#define PORT 8080

#define PRIVATEKEY "private.key"
#define CHAINFILE "chain.crt"

typedef struct {
    char *reg_match;
    void (*function) (SSL *ssl, char *rec);
} handle_t;

int server_init(handle_t *handlers);
void server_run();

int send_file(SSL *ssl, char *filename);

#endif
