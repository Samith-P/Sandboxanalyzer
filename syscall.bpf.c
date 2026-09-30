#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct syscall_event {
    __u32 pid;
    __u32 syscall_id;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 *target;
    __u32 pid;
    struct syscall_event *event;

    pid = bpf_get_current_pid_tgid() >> 32;

    target = bpf_map_lookup_elem(&target_pid, &key);

    if (!target)
        return 0;

    if (pid != *target)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (!event)
        return 0;

    event->pid = pid;
    event->syscall_id = ctx->id;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    return 0;
}

