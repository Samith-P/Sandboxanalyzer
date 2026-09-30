#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

int main() {

    printf("SaMOSA suspicious behavior test\n");

    // Give eBPF monitor time to attach
    sleep(10);

    // File activity
    FILE *f = fopen("test_file.txt", "w");

    if (f != NULL) {
        fprintf(f, "test data\n");
        fclose(f);
    }

    // Process creation
    pid_t pid = fork();

    if (pid == 0) {
        printf("Child process running\n");
        sleep(5);
        return 0;
    }

    // Network-related syscall
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock >= 0) {
        close(sock);
    }

    // Wait for child
    wait(NULL);

    // Keep parent alive
    sleep(10);

    return 0;
}
