#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"


SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, FILEOPEN_EVENT_NB_RING * sizeof(struct file_event));
} events;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(void* ctx)
{
    struct file_event *data;
    data = bpf_ringbuf_reserve(&events, sizeof(struct file_event), 0);
    if (!data)
        return 0;

    data->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    char *filename_ptr = NULL;
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), (void *)ctx + 24);
    bpf_probe_read_user_str(data->filename, sizeof(data->filename), filename_ptr);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    __u64 flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), (void *)ctx + 32);
    data->flags = (__u32)flags;  
    
    __u64 mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), (void *)ctx + 40);
    data->mode = (__u32)mode;


    bpf_ringbuf_submit(data, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
