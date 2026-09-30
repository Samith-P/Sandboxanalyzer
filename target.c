#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("Target process started. PID: %d\n", getpid());
    fflush(stdout);

    while (1) {
        getpid();
        getppid();
        sleep(1);
    }

    return 0;
}
