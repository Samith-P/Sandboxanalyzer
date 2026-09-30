/* file_test.c - creates, writes, reads, and deletes a file in /tmp. */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void) {
    const char *path = "/tmp/samosa_file_test.txt";
    char buf[64];
    struct stat st;

    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 1; }
    write(fd, "hello samosa\n", 13);
    close(fd);

    stat(path, &st);

    fd = open(path, O_RDONLY);
    read(fd, buf, sizeof(buf));
    close(fd);

    unlink(path);   /* file deletion */
    puts("file_test: done");
    return 0;
}

