//go:build ignore

// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct value_t
{
    u64 counter;
    char cmd[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct value_t);
} counter_table SEC(".maps");

SEC("kprobe/hello")
int hello(void *ctx)
{
    u64 cookie;
    u64 uid;
    char cmd[16];

    cookie = bpf_get_attach_cookie(ctx);
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct value_t val = {};
    struct value_t *p = bpf_map_lookup_elem(&counter_table, &uid);

    if (p != 0)
    {
        val = *p;
    }
    val.counter++;

    if (cookie == 1)
    {
        bpf_get_current_comm(val.cmd, sizeof(cmd));
    }


    bpf_map_update_elem(&counter_table, &uid, &val.counter, BPF_ANY);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";