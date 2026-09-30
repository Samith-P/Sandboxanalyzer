#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>

#include "syscall.bpf.skel.h"

static volatile sig_atomic_t exiting = 0;
static FILE *log_file = NULL;

static void sig_handler(int sig)
{
    exiting = 1;
}

struct syscall_event {
    __u32 pid;
    __u32 syscall_id;
    char comm[16];
};

const char *syscall_name(int id)
{
    switch (id) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 9: return "mmap";
        case 10: return "mprotect";
        case 11: return "munmap";
        case 12: return "brk";
        case 13: return "rt_sigaction";
        case 14: return "rt_sigprocmask";
        case 21: return "access";
        case 39: return "getpid";
        case 41: return "socket";
        case 42: return "connect";
        case 44: return "sendto";
        case 45: return "recvfrom";
        case 56: return "clone";
        case 57: return "fork";
        case 59: return "execve";
        case 60: return "exit";
        case 61: return "wait4";
        case 62: return "kill";
        case 72: return "fcntl";
        case 79: return "getcwd";
        case 80: return "chdir";
        case 87: return "unlink";
        case 89: return "readlink";
        case 97: return "getrlimit";
        case 102: return "getuid";
        case 104: return "setuid";
        case 105: return "getgid";
        case 106: return "setgid";
        case 110: return "getppid";
        case 158: return "arch_prctl";
        case 202: return "futex";
        case 217: return "getdents64";
        case 218: return "set_tid_address";
        case 228: return "clock_gettime";
        case 230: return "clock_nanosleep";
        case 231: return "exit_group";
        case 257: return "openat";
        case 262: return "newfstatat";
        case 273: return "set_robust_list";
        case 302: return "prlimit64";
        case 318: return "getrandom";
        case 435: return "clone3";
        default: return "unknown";
    }
}

#define MAX_SYSCALLS 512

static unsigned long syscall_counts[MAX_SYSCALLS];

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct syscall_event *event = data;

    const char *name = syscall_name(event->syscall_id);

    if (event->syscall_id < MAX_SYSCALLS)
        syscall_counts[event->syscall_id]++;

    printf("PID: %-8u PROCESS: %-16s SYSCALL: %-20s (%u)\n",
           event->pid,
           event->comm,
           name,
           event->syscall_id);

    if (log_file) {
        fprintf(log_file, "%u,%s,%u,%s\n",
                event->pid,
                event->comm,
                event->syscall_id,
                name);

        fflush(log_file);
    }

    return 0;
}

static int write_message(int fd, const char *msg)
{
    size_t len = strlen(msg);
    ssize_t written = write(fd, msg, len);

    return written == (ssize_t)len ? 0 : -1;
}

static int read_pid(int fd, __u32 *pid)
{
    char buffer[32];
    ssize_t n;

    n = read(fd, buffer, sizeof(buffer) - 1);

    if (n <= 0)
        return -1;

    buffer[n] = '\0';

    char *end;
    unsigned long value = strtoul(buffer, &end, 10);

    if (end == buffer || value == 0 || value > UINT32_MAX)
        return -1;

    *pid = (__u32)value;

    return 0;
}

int main(int argc, char **argv)
{
    struct syscall_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;

    int err = 0;

    if (argc != 4) {
        fprintf(stderr,
                "Usage: %s <log-file> <pid-pipe> <ready-pipe>\n",
                argv[0]);
        return 1;
    }

    const char *log_path = argv[1];

    int pid_fd = atoi(argv[2]);
    int ready_fd = atoi(argv[3]);

    if (pid_fd < 0 || ready_fd < 0) {
        fprintf(stderr, "Invalid pipe descriptors\n");
        return 1;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /*
     * Load BPF program.
     */

    skel = syscall_bpf__open_and_load();

    if (!skel) {
        fprintf(stderr,
                "Failed to open/load BPF skeleton\n");

        return 1;
    }

    /*
     * Attach BPF BEFORE the target starts.
     */

    err = syscall_bpf__attach(skel);

    if (err) {
        fprintf(stderr,
                "Failed to attach BPF program: %d\n",
                err);

        goto cleanup;
    }

    printf("[+] BPF monitor attached.\n");

    /*
     * Tell sandbox_runner that the monitor
     * is ready to receive the target PID.
     */

    if (write_message(ready_fd, "READY\n") != 0) {
        fprintf(stderr,
                "Failed to signal runner\n");

        err = -1;
        goto cleanup;
    }

    /*
     * Wait for target PID.
     */

    __u32 pid;

    if (read_pid(pid_fd, &pid) != 0) {
        fprintf(stderr,
                "Failed to receive target PID\n");

        err = -1;
        goto cleanup;
    }

    printf("[+] Received target PID: %u\n", pid);

    /*
     * Put target PID into BPF map.
     */

    __u32 key = 0;

    err = bpf_map__update_elem(
        skel->maps.target_pid,
        &key,
        sizeof(key),
        &pid,
        sizeof(pid),
        BPF_ANY
    );

    if (err) {
        fprintf(stderr,
                "Failed to set target PID: %d\n",
                err);

        goto cleanup;
    }

    printf("[+] Target PID installed in BPF map.\n");

    /*
     * Create ring buffer.
     */

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(stderr,
                "Failed to create ring buffer\n");

        err = -1;
        goto cleanup;
    }

    /*
     * Open syscall CSV.
     */

    log_file = fopen(log_path, "w");

    if (!log_file) {
        perror("Failed to open syscall log");
        err = -1;
        goto cleanup;
    }

    fprintf(log_file,
            "pid,process,syscall_id,syscall\n");

    fflush(log_file);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /*
     * Tell sandbox_runner that everything is ready.
     */

    if (write_message(ready_fd, "TRACE_READY\n") != 0) {
        fprintf(stderr,
                "Failed to signal TRACE_READY\n");

        err = -1;
        goto cleanup;
    }

    printf("[+] Tracing PID %u...\n\n", pid);

    /*
     * Main event loop.
     */

    while (!exiting) {

        err = ring_buffer__poll(rb, 100);

        if (err < 0) {

            if (err == -EINTR) {
                err = 0;
                break;
            }

            fprintf(stderr,
                    "Ring buffer polling failed: %d\n",
                    err);

            break;
        }
    }

    printf("\n========== SYSCALL SUMMARY ==========\n");

    for (int i = 0; i < MAX_SYSCALLS; i++) {

        if (syscall_counts[i] > 0) {

            printf("%-20s : %lu\n",
                   syscall_name(i),
                   syscall_counts[i]);
        }
    }

    printf("=====================================\n");

cleanup:

    if (log_file)
        fclose(log_file);

    ring_buffer__free(rb);

    if (skel)
        syscall_bpf__destroy(skel);

    return err < 0 ? 1 : 0;
}
