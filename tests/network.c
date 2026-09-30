/* network_test.c - tries a TCP connection to localhost only.
 * Nothing needs to be listening: the connect() syscall is what we want. */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        perror("connect (expected to fail if nothing is listening)");
    else
        send(s, "hello", 5, 0);

    close(s);
    return 0;
}
