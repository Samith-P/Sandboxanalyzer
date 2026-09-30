/* benign.c - plain computation + printing. No files, network, or exec. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    int *arr = malloc(1000 * sizeof(int));
    long sum = 0;

    for (int i = 0; i < 1000; i++) {
        arr[i] = i * 2;
        sum += arr[i];
    }

    printf("benign: pid=%d sum=%ld\n", getpid(), sum);
    free(arr);
    return 0;
}
