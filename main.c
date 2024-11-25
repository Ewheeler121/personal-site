#include <stdlib.h>
#include "network.h"

void static_files_handlers(SSL *ssl, char *received);

handle_t handles[] = {
    {NULL, static_files_handlers}
};

int main() {
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
