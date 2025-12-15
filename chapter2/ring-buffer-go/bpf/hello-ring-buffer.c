#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} output SEC(".maps");

struct event_t
{
    long dfd;
    char command[16];
    char filename[128];
};

/* All the steps carried out below are to ensure verifier passes before loading the program */
SEC("tracepoint/syscalls/sys_enter_openat")
int hello_ring_buff(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *event;
    char sfilename[128];
    char scomm[16];
    int ret;
    int to_copy_fname;
    int to_copy_comm;

    /* 1) Read user filename into a bounded stack buffer */
    ret = bpf_probe_read_user_str(sfilename, sizeof(sfilename),
                                  (const char *)ctx->args[1]);

    if (ret <= 0)
    {
        /* could not read; set empty */
        sfilename[0] = '\0';
        ret = 1; /* keep ret positive for copy logic below (copy at least '\0') */
    }

     /* 2) Read current comm into stack buffer (helper writes into stack) */
    bpf_get_current_comm(scomm, sizeof(scomm));

    /* 3) Reserve ringbuf space AFTER we have concrete data on the stack
     It is required to reserve space from the ring buffer, fill it
     and then submit it (see bpf_ringbuf_submit below) */
    event = bpf_ringbuf_reserve(&output, sizeof(struct event_t), 0);
    if (!event)
        return 0;

    /*
        long dfd      = ctx->args[0];
        long filename = ctx->args[1];
        long flags    = ctx->args[2];
        long mode     = ctx->args[3];
    */

    /* 4) Fill fixed/known fields */
    event->dfd = (long)ctx->args[0];

    /* 5) clamp sizes to the event fields */
    to_copy_fname = ret;
    if (to_copy_fname > (int)sizeof(event->filename))
        to_copy_fname = sizeof(event->filename);

    to_copy_comm = sizeof(scomm);
    if (to_copy_comm > (int)sizeof(event->command))
        to_copy_comm = sizeof(event->command);

    /* 6) copy stack -> ringbuf using bpf_probe_read_kernel (verifier-accepted) */
    bpf_probe_read_kernel(event->filename, to_copy_fname, sfilename);
    bpf_probe_read_kernel(event->command, to_copy_comm, scomm);

    /* ensure NUL terminated for safety */
    event->filename[sizeof(event->filename) - 1] = '\0';

    /* 7) debug prints (bpf_printk macro) */
    bpf_printk("File %d - %s", event->dfd, event->filename);
    bpf_printk("     opened by:%s", event->command);

    /* 8) submit */
    bpf_ringbuf_submit(event, 0);

    return 0;
}