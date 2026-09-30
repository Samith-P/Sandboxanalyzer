/* suspicious_test.c - harmless program that TOUCHES the patterns the
 * analyzer looks for: network + process creation/exec + file deletion.
 * It only connects to localhost, runs /bin/echo, and deletes its own
 * temp file. */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

int main(void) {
    const char *path = "/tmp/samosa_susp_test.txt";

    /* 1. network: connect to localhost (may fail, that's fine) */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    connect(s, (struct sockaddr *)&addr, sizeof(addr));
    close(s);

    /* 2. drop a file */
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(fd, "payload\n", 8);
    close(fd);

    /* 3. process creation + execution */
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/echo", "echo", "child process executed", (char *)NULL);
        _exit(1);
    }
    waitpid(pid, NULL, 0);

    /* 4. delete the file */
    unlink(path);
    return 0;
}
