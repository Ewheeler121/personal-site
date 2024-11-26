#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "network.h"

void static_files_handlers(SSL *ssl, char *request);
void handle_hitcounter(SSL *ssl, char *request);

int hitcounter = 0;
sqlite3 *database;

handle_t handles[] = {
    {"^GET /hit-counter$", handle_hitcounter},
    {NULL, static_files_handlers}
};

int main() {
    if(sqlite3_open("database.db", &database) != SQLITE_OK) {
        fprintf(stderr, "error opening database\n");
        return EXIT_FAILURE;
    }

    if(server_init(handles) == 1) {
        return EXIT_FAILURE;
    }
    server_run();

    return EXIT_SUCCESS;
}

void static_files_handlers(SSL *ssl, char *request) {
    char *head_start = strstr(request, "GET /");
    char *head_end = strstr(request, " HTTP/1.1");
    if(head_start == NULL || head_end == NULL) {
        SSL_write(ssl, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", 48);
        return;
    }
    head_start += 5;
    if(head_end - head_start) {
        char *head = alloca((int)(head_end - head_start) + 9);
        snprintf(head, (int)(head_end - head_start) + 8, "static/%s", head_start);
        send_file(ssl, head);
    } else {
        send_file(ssl, "static/index.html");
    }

}

void handle_hitcounter(SSL *ssl, char *request) {
    hitcounter++;
    char buff[20];
    char response[500];
    snprintf(response, 500, "<h4 style=\"margin: 0 0\">visits: %d</h4>", hitcounter);
    snprintf(buff, 20, "%ld", strlen(response));
    SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ", 58);
    SSL_write(ssl, buff, strlen(buff));
    SSL_write(ssl, "\r\n\r\n", 4);
    SSL_write(ssl, response, strlen(response));
    SSL_write(ssl, "\r\n\r\n", 4);
}

int comment_callback(void *data, int argc, char **argv, char **azColName) {
    size_t response_size = strlen(argv[1]) + strlen(argv[3]) + 13;
    if(argv[2] != NULL) {
        response_size += strlen(argv[2]) + 2;
    }
    char *response = alloca(response_size);
    if(argv[2] != NULL) {
        sprintf(response, "<h4>%s (%s): %s</h4>", argv[1], argv[2], argv[3]);
    } else {
        sprintf(response, "<h4>%s: %s</h4>", argv[1], argv[3]);
    }
    SSL_write((SSL *)data, response, strlen(response));
    return 0;
}

void handle_comments(SSL *ssl, char *request) {
    SSL_write(ssl, "<div class=\"comments\">", 22);
    sqlite3_exec(database, "SELECT * FROM Comments", comment_callback, (void *)ssl, NULL);
    SSL_write(ssl, "</div>", 6);
}
