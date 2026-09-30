#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <errno.h>

static pid_t target_pid = -1;
static pid_t monitor_pid = -1;

static FILE *runner_log = NULL;

static int pid_pipe[2];
static int ready_pipe[2];
static int release_pipe[2];

static void log_msg(const char *msg)
{
    printf("%s", msg);
    fflush(stdout);

    if (runner_log) {
        fprintf(runner_log, "%s", msg);
        fflush(runner_log);
    }
}

static void stop_processes(void)
{
    char msg[128];

    if (target_pid > 0) {

        snprintf(msg,
                 sizeof(msg),
                 "[+] Stopping target (PID %d)...\n",
                 target_pid);

        log_msg(msg);

        kill(target_pid, SIGTERM);
    }

    if (monitor_pid > 0) {

        snprintf(msg,
                 sizeof(msg),
                 "[+] Stopping syscall monitor (PID %d)...\n",
                 monitor_pid);

        log_msg(msg);

        kill(monitor_pid, SIGTERM);
    }

    /*
     * Release target if it is still waiting.
     */

    if (release_pipe[1] >= 0) {
        write(release_pipe[1], "STOP\n", 5);
    }
}

static int wait_for_message(int fd,
                            const char *expected)
{
    char buffer[64];

    ssize_t n = read(fd,
                     buffer,
                     sizeof(buffer) - 1);

    if (n <= 0)
        return -1;

    buffer[n] = '\0';

    if (strstr(buffer, expected) == NULL)
        return -1;

    return 0;
}

int main(int argc, char **argv)
{
    int status;

    const int RUN_TIME = 15;

    if (argc != 2) {

        fprintf(stderr,
                "Usage: %s <executable>\n",
                argv[0]);

        return 1;
    }

    char *target_program = argv[1];

    struct stat st;

    if (stat(target_program, &st) != 0) {

        perror("[!] Cannot access target");

        return 1;
    }

    if (access(target_program, X_OK) != 0) {

        fprintf(stderr,
                "[!] Target is not executable: %s\n",
                target_program);

        return 1;
    }

    printf("[+] Target program: %s\n",
           target_program);

    mkdir("results", 0755);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    char run_dir[128];

    snprintf(run_dir,
             sizeof(run_dir),
             "results/run_%04d%02d%02d_%02d%02d%02d",
             t->tm_year + 1900,
             t->tm_mon + 1,
             t->tm_mday,
             t->tm_hour,
             t->tm_min,
             t->tm_sec);

    mkdir(run_dir, 0755);

    char runner_log_path[256];

    snprintf(runner_log_path,
             sizeof(runner_log_path),
             "%s/runner.log",
             run_dir);

    runner_log = fopen(runner_log_path, "w");

    if (!runner_log) {

        perror("[!] Cannot create runner.log");

        return 1;
    }

    char msg[256];

    snprintf(msg,
             sizeof(msg),
             "[+] Results directory: %s\n",
             run_dir);

    log_msg(msg);

    log_msg("[+] Starting sandbox runner...\n");

    /*
     * Create communication pipes.
     *
     * pid_pipe:
     * runner -> monitor
     *
     * ready_pipe:
     * monitor -> runner
     *
     * release_pipe:
     * runner -> target
     */

    if (pipe(pid_pipe) < 0 ||
        pipe(ready_pipe) < 0 ||
        pipe(release_pipe) < 0) {

        perror("[!] pipe");

        fclose(runner_log);

        return 1;
    }

    /*
     * Start monitor FIRST.
     */

    monitor_pid = fork();

    if (monitor_pid < 0) {

        perror("fork monitor");

        fclose(runner_log);

        return 1;
    }

    if (monitor_pid == 0) {

        char pid_fd_str[32];
        char ready_fd_str[32];
        char csv_path[256];

        /*
         * Child monitor only needs:
         *
         * pid_pipe[0]
         * ready_pipe[1]
         */

        close(pid_pipe[1]);
        close(ready_pipe[0]);

        close(release_pipe[0]);
        close(release_pipe[1]);

        snprintf(pid_fd_str,
                 sizeof(pid_fd_str),
                 "%d",
                 pid_pipe[0]);

        snprintf(ready_fd_str,
                 sizeof(ready_fd_str),
                 "%d",
                 ready_pipe[1]);

        snprintf(csv_path,
                 sizeof(csv_path),
                 "%s/syscall_log.csv",
                 run_dir);

        char output_path[256];

        snprintf(output_path,
                 sizeof(output_path),
                 "%s/syscall_output.log",
                 run_dir);

        FILE *output = fopen(output_path, "w");

        if (!output) {

            perror("[!] Cannot create syscall_output.log");

            exit(1);
        }

        dup2(fileno(output), STDOUT_FILENO);
        dup2(fileno(output), STDERR_FILENO);

        fclose(output);

        execl("./syscall",
              "./syscall",
              csv_path,
              pid_fd_str,
              ready_fd_str,
              NULL);

        perror("[!] Failed to execute syscall monitor");

        exit(1);
    }

    /*
     * Parent no longer needs monitor-side pipe ends.
     */

    close(pid_pipe[0]);
    close(ready_pipe[1]);

    snprintf(msg,
             sizeof(msg),
             "[+] Syscall monitor PID: %d\n",
             monitor_pid);

    log_msg(msg);

    /*
     * Wait until BPF is actually attached.
     */

    log_msg("[+] Waiting for eBPF monitor to become ready...\n");

    if (wait_for_message(ready_pipe[0], "READY") != 0) {

        log_msg("[!] Monitor failed to become ready.\n");

        kill(monitor_pid, SIGTERM);

        waitpid(monitor_pid, NULL, 0);

        fclose(runner_log);

        return 1;
    }

    log_msg("[+] eBPF monitor attached and ready.\n");

    /*
     * NOW create target.
     *
     * The target child will WAIT before exec().
     */

    target_pid = fork();

    if (target_pid < 0) {

        perror("fork target");

        kill(monitor_pid, SIGTERM);

        waitpid(monitor_pid, NULL, 0);

        fclose(runner_log);

        return 1;
    }

    if (target_pid == 0) {

        char release_buffer[16];

        /*
         * Wait until monitor has the PID.
         */

        ssize_t n = read(release_pipe[0],
                         release_buffer,
                         sizeof(release_buffer));

        if (n <= 0)
            exit(1);

        /*
         * Now execute target.
         */

        execl(target_program,
              target_program,
              NULL);

        perror("[!] Failed to execute target");

        exit(1);
    }

    close(release_pipe[0]);

    snprintf(msg,
             sizeof(msg),
             "[+] Target created with PID: %d\n",
             target_pid);

    log_msg(msg);

    /*
     * Send target PID to monitor.
     */

    char pid_str[32];

    snprintf(pid_str,
             sizeof(pid_str),
             "%d\n",
             target_pid);

    if (write(pid_pipe[1],
              pid_str,
              strlen(pid_str)) < 0) {

        perror("[!] Failed to send target PID");

        stop_processes();

        waitpid(target_pid, NULL, 0);
        waitpid(monitor_pid, NULL, 0);

        fclose(runner_log);

        return 1;
    }

    close(pid_pipe[1]);

    log_msg("[+] Target PID sent to eBPF monitor.\n");

    /*
     * Wait until monitor has actually written
     * the PID into the BPF map.
     */

    log_msg("[+] Waiting for syscall tracing to become ready...\n");

    if (wait_for_message(ready_pipe[0], "TRACE_READY") != 0) {

        log_msg("[!] Monitor failed to initialize tracing.\n");

        stop_processes();

        waitpid(target_pid, NULL, 0);
        waitpid(monitor_pid, NULL, 0);

        fclose(runner_log);

        return 1;
    }

    close(ready_pipe[0]);

    log_msg("[+] Syscall tracing ready.\n");

    /*
     * Release target.
     */

    if (write(release_pipe[1],
              "START\n",
              6) < 0) {

        perror("[!] Failed to release target");

        stop_processes();

        waitpid(target_pid, NULL, 0);
        waitpid(monitor_pid, NULL, 0);

        fclose(runner_log);

        return 1;
    }

    close(release_pipe[1]);

    log_msg("[+] Target released.\n");

    snprintf(msg,
             sizeof(msg),
             "[+] Sandbox running for %d seconds...\n",
             RUN_TIME);

    log_msg(msg);

    /*
     * Run sandbox.
     */

    sleep(RUN_TIME);

    log_msg("\n[+] Time limit reached.\n");

    stop_processes();

    waitpid(target_pid, &status, 0);

    waitpid(monitor_pid, NULL, 0);

    log_msg("[+] Sandbox finished.\n");

    fclose(runner_log);

    return 0;
}
