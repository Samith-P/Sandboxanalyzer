#!/usr/bin/env python3
"""
SaMOSA analyzer: turns syscall_log.csv into a behavioural risk report.

Pipeline position:
    target -> sandbox_runner -> eBPF syscall monitor -> syscall_log.csv -> analyzer.py

IMPORTANT: the output is a BEHAVIOURAL RISK ASSESSMENT, not a malware verdict.
It only looks at which system calls were made (not their arguments), so it
can be wrong in both directions.

Usage:
    python3 analyzer.py syscall_log.csv analysis_report.txt

Standard library only.
"""

import csv
import re
import sys
from collections import Counter
from datetime import datetime

# ---------------------------------------------------------------
# 1. SETTINGS (all tunable numbers live here so they are easy to explain)
# ---------------------------------------------------------------
MEDIUM_THRESHOLD = 3          # score >= 3  -> MEDIUM
HIGH_THRESHOLD = 6            # score >= 6  -> HIGH
BULK_FILE_OP_THRESHOLD = 50   # this many delete/rename calls = "bulk" activity
TOP_N = 10                    # how many top syscalls to print

# Accepted names for the syscall column (first match wins)
COLUMN_ALIASES = ("syscall", "syscall_name", "name", "sys", "call", "event")

# ---------------------------------------------------------------
# 2. SYSCALL CLASSIFICATION TABLE: category -> set of syscalls
# ---------------------------------------------------------------
CATEGORIES = {
    "File I/O": {
        "open", "openat", "openat2", "creat", "close", "read", "write",
        "pread64", "pwrite64", "readv", "writev", "preadv", "pwritev",
        "lseek", "sendfile", "copy_file_range", "splice", "truncate",
        "ftruncate", "fsync", "fdatasync", "dup", "dup2", "dup3", "fcntl",
        "ioctl", "flock", "close_range",
    },
    "File Metadata / Permissions": {
        "stat", "lstat", "fstat", "newfstatat", "statx", "access",
        "faccessat", "faccessat2", "readlink", "readlinkat", "chmod",
        "fchmod", "fchmodat", "chown", "fchown", "lchown", "fchownat",
        "utime", "utimes", "utimensat", "getxattr", "setxattr",
        "listxattr", "removexattr",
    },
    "File Deletion / Rename": {
        "unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2",
    },
    "Directory Operations": {
        "getdents", "getdents64", "mkdir", "mkdirat", "chdir", "fchdir",
        "getcwd", "chroot", "link", "linkat", "symlink", "symlinkat",
    },
    "Filesystem / Mounts": {
        "mount", "umount2", "pivot_root", "statfs", "fstatfs",
    },
    "Network": {
        "socket", "connect", "bind", "listen", "accept", "accept4",
        "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
        "shutdown", "getsockname", "getpeername", "setsockopt",
        "getsockopt", "socketpair",
    },
    "Process Creation": {"clone", "clone3", "fork", "vfork"},
    "Process Execution": {"execve", "execveat"},
    "Process Control / Signals": {
        "kill", "tkill", "tgkill", "ptrace", "prctl", "wait4", "waitid",
        "exit", "exit_group", "rt_sigaction", "rt_sigprocmask",
        "rt_sigreturn", "sigaltstack", "setsid", "setpgid", "seccomp",
        "unshare", "setns", "pidfd_open", "pidfd_send_signal",
    },
    "Memory Management": {
        "mmap", "mremap", "mprotect", "munmap", "brk", "madvise", "mlock",
        "munlock", "mlockall", "memfd_create", "process_vm_readv",
        "process_vm_writev",
    },
    "IPC / Synchronization": {
        "pipe", "pipe2", "futex", "eventfd", "eventfd2", "shmget", "shmat",
        "shmdt", "shmctl", "semget", "semop", "semctl", "msgget", "msgsnd",
        "msgrcv", "poll", "ppoll", "select", "pselect6", "epoll_create",
        "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    },
    "Privilege / Identity": {
        "getuid", "geteuid", "getgid", "getegid", "setuid", "setgid",
        "setreuid", "setregid", "setresuid", "setresgid", "capget",
        "capset", "getgroups", "setgroups",
    },
    "System Info / Time": {
        "uname", "sysinfo", "getrlimit", "setrlimit", "prlimit64",
        "getrusage", "getrandom", "gettimeofday", "clock_gettime",
        "clock_nanosleep", "nanosleep", "time", "getpid", "getppid",
        "gettid", "sched_yield", "sched_getaffinity", "arch_prctl",
        "set_tid_address", "set_robust_list", "rseq",
    },
    "Kernel / Modules": {
        "init_module", "finit_module", "delete_module", "bpf", "reboot",
        "kexec_load", "perf_event_open",
    },
}

# Reverse lookup: syscall -> category
SYSCALL_TO_CATEGORY = {
    sc: cat for cat, group in CATEGORIES.items() for sc in group
}

# Syscalls worth a closer look (short labels; each has legitimate uses too)
NOTABLE = {
    "execve": "Launches a program",
    "execveat": "Launches a program",
    "connect": "Opens a connection",
    "bind": "Binds a socket",
    "listen": "Listens for connections",
    "accept": "Accepts a connection",
    "accept4": "Accepts a connection",
    "ptrace": "Traces another process",
    "process_vm_writev": "Writes another process's memory",
    "process_vm_readv": "Reads another process's memory",
    "memfd_create": "Anonymous in-memory file",
    "chroot": "Changes root directory",
    "mount": "Mounts a filesystem",
    "pivot_root": "Swaps root filesystem",
    "init_module": "Loads a kernel module",
    "finit_module": "Loads a kernel module",
    "delete_module": "Unloads a kernel module",
    "kexec_load": "Loads a new kernel",
    "bpf": "Uses eBPF",
    "setuid": "Changes user id",
    "setresuid": "Changes user id",
    "seccomp": "Installs a syscall filter",
    "kill": "Signals another process",
    "unlink": "Deletes a file",
    "unlinkat": "Deletes a file",
    "unshare": "Creates new namespaces",
}


# ---------------------------------------------------------------
# 3. CSV PARSING
# ---------------------------------------------------------------
def normalise_name(raw):
    """Lower-case, trim, and strip common kernel prefixes (sys_, __x64_sys_)."""
    name = raw.strip().strip('"\'').lower()
    for prefix in ("__x64_sys_", "__ia32_sys_", "sys_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name


def read_syscalls(path):
    """
    Read syscall names from the CSV.

    Tolerates: UTF-8 BOM, blank lines, different header case/spacing,
    alternative column names, and , ; tab | delimiters.
    Returns (list_of_syscall_names, number_of_skipped_rows).
    """
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        sample = f.read(4096)
        f.seek(0)

        # Guess the delimiter from the first non-empty line.
        first_line = next((l for l in sample.splitlines() if l.strip()), "")
        if not first_line:
            raise ValueError("CSV file is empty")
        delimiter = max(",;\t|", key=first_line.count)   # ties -> ","

        reader = csv.DictReader(f, delimiter=delimiter, skipinitialspace=True)
        if not reader.fieldnames:
            raise ValueError("CSV file has no header row")

        # Map normalised header -> real header, then pick the syscall column.
        headers = {h.strip().lower(): h for h in reader.fieldnames if h}
        column = next((headers[a] for a in COLUMN_ALIASES if a in headers), None)
        if column is None:
            raise ValueError(
                f"No syscall column found (looked for {COLUMN_ALIASES}). "
                f"Columns present: {reader.fieldnames}"
            )

        names, skipped = [], 0
        for row in reader:
            name = normalise_name(row.get(column) or "")
            # valid syscall names are letters/digits/underscore only
            if name and re.fullmatch(r"[a-z0-9_]+", name):
                names.append(name)
            else:
                skipped += 1
    return names, skipped


# ---------------------------------------------------------------
# 4. RISK RULES  (simple, transparent, combination based)
# ---------------------------------------------------------------
def evaluate_rules(counts):
    """
    Each rule = (title, points, condition, reason).
    Common behaviours (network, file I/O, exec...) are worth 0 points alone.
    Points are only awarded for unusual syscalls or risky COMBINATIONS.
    """
    def n(*names):                     # total calls across these syscalls
        return sum(counts[x] for x in names)

    execs = n("execve", "execveat") > 0

    rules = [
        # ---- Combinations of common behaviours ----
        ("Outbound connection + program execution", 2,
         n("connect") > 0 and execs,
         "Connects out and launches other programs."),

        ("Socket connected to a process (connect/accept + dup2/dup3 + exec)", 3,
         n("connect", "accept", "accept4") > 0
         and n("dup2", "dup3") > 0 and execs,
         "Socket duplicated onto stdin/stdout, then exec (reverse-shell pattern)."),

        ("Listening server socket (bind + listen)", 1,
         n("bind") > 0 and n("listen") > 0,
         "Opens a listening port."),

        ("Privilege change + program execution", 2,
         n("setuid", "setgid", "setreuid", "setregid",
           "setresuid", "setresgid") > 0 and execs,
         "Changes user/group id, then runs a program."),

        (f"Bulk file deletion/rename (>= {BULK_FILE_OP_THRESHOLD} calls)", 2,
         n("unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2")
         >= BULK_FILE_OP_THRESHOLD,
         "Many deletes/renames in one run."),

        # ---- Rarely-needed syscalls ----
        ("Fileless execution (memfd_create + exec)", 4,
         n("memfd_create") > 0 and execs,
         "In-memory program created, then executed."),

        ("Writes into another process's memory (process_vm_writev)", 4,
         n("process_vm_writev") > 0,
         "Possible code injection."),

        ("Reads another process's memory (process_vm_readv)", 2,
         n("process_vm_readv") > 0,
         "Reads memory of another process."),

        ("Process tracing (ptrace)", 3,
         n("ptrace") > 0,
         "Traces/controls another process (or itself)."),

        ("Kernel module / kexec activity", 4,
         n("init_module", "finit_module", "delete_module", "kexec_load") > 0,
         "Loads or removes kernel code."),

        ("eBPF use (bpf)", 1,
         n("bpf") > 0,
         "Loads eBPF programs."),

        ("Mount / chroot / pivot_root activity", 2,
         n("mount", "umount2", "chroot", "pivot_root") > 0,
         "Changes the filesystem view."),

        ("Installs a seccomp filter", 1,
         n("seccomp") > 0,
         "Restricts its own syscalls."),
    ]

    return [(title, pts, reason) for title, pts, cond, reason in rules if cond]


def risk_level(score):
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


LEVEL_REASON = {
    "LOW": "No strong risk indicators observed.",
    "MEDIUM": "Some behaviours sometimes linked to malicious programs; "
              "manual review advised.",
    "HIGH": "Multiple strong indicators observed; investigate further.",
}


# ---------------------------------------------------------------
# 5. REPORT
# ---------------------------------------------------------------
def build_report(input_file, total, skipped, counts):
    # Category totals (syscalls not in the table are "Unclassified")
    cat_total = Counter()
    unclassified = 0
    for name, c in counts.items():
        cat = SYSCALL_TO_CATEGORY.get(name)
        if cat:
            cat_total[cat] += c
        else:
            unclassified += c

    hits = evaluate_rules(counts)
    score = sum(p for _, p, _ in hits)
    level = risk_level(score)

    def pct(x):
        return 100 * x / total if total else 0

    r = []
    add = r.append
    bar = "=" * 60

    add(bar)
    add("SaMOSA - BEHAVIOURAL RISK REPORT")
    add(bar)
    add(f"Input file      : {input_file}")
    add(f"Generated       : {datetime.now():%Y-%m-%d %H:%M:%S}")
    add(f"Total syscalls  : {total}")
    add(f"Unique syscalls : {len(counts)}")
    if skipped:
        add(f"Skipped rows    : {skipped}")
    add("")

    # ---- Category frequencies ----
    add("CATEGORY FREQUENCIES")
    add("-" * 60)
    for cat, c in sorted(cat_total.items(), key=lambda x: -x[1]):
        add(f"  {cat:<30} {c:>7}  {pct(c):5.1f}%")
    if unclassified:
        add(f"  {'Unclassified':<30} {unclassified:>7}  {pct(unclassified):5.1f}%")
    add("")

    # ---- Top syscalls ----
    add(f"TOP {TOP_N} SYSCALLS")
    add("-" * 60)
    for name, c in counts.most_common(TOP_N):
        add(f"  {name:<30} {c:>7}  {pct(c):5.1f}%")
    add("")

    # ---- Notable behaviours ----
    add("NOTABLE BEHAVIOURS")
    add("-" * 60)
    found = [(n, counts[n], why) for n, why in NOTABLE.items() if n in counts]
    if found:
        for n, c, why in sorted(found, key=lambda x: -x[1]):
            add(f"  - {n} (x{c}): {why}")
    else:
        add("  None")
    add("")

    # ---- Risk rules ----
    add("RISK RULES TRIGGERED")
    add("-" * 60)
    if hits:
        for title, pts, reason in sorted(hits, key=lambda x: -x[1]):
            add(f"  [+{pts}] {title}")
            add(f"        {reason}")
    else:
        add("  None")
    add("")

    # ---- Final assessment ----
    add(bar)
    add(f"  RISK SCORE : {score}")
    add(f"  RISK LEVEL : {level}")
    if hits:
        top_title = max(hits, key=lambda x: x[1])[0]
        add(f"  REASON     : {LEVEL_REASON[level]}")
        add(f"               Top factor: {top_title.split(' (')[0]}")
    else:
        add(f"  REASON     : {LEVEL_REASON[level]} No risk rules triggered.")
    add(bar)
    add("This is a behavioural risk assessment based on syscall names only.")
    add("It is NOT proof that a program is, or is not, malware.")

    return "\n".join(r)


def analyze(input_file, output_file):
    syscalls, skipped = read_syscalls(input_file)
    if not syscalls:
        raise ValueError("No valid syscall events found; nothing to assess")
    counts = Counter(syscalls)
    report = build_report(input_file, len(syscalls), skipped, counts)
    print(report)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report + "\n")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Usage: python3 analyzer.py <syscall_log.csv> [analysis_report.txt]")
        sys.exit(1)
    out = sys.argv[2] if len(sys.argv) == 3 else "analysis_report.txt"
    try:
        analyze(sys.argv[1], out)
    except (OSError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)
