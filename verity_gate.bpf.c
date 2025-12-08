#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

extern int bpf_verify_dm_verity_digest(struct file *file, __u8 *trusted_digest, __u32 trusted_digest_len) __ksym;
extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
extern void bpf_put_file(struct file *file) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[32]);
} allowed_root_hash SEC(".maps");

SEC("lsm.s/bpf")
int BPF_PROG(verity_gate, int cmd, union bpf_attr *attr, unsigned int size)
{
    __u8 *trusted_digest;
    struct file *exe_file;
    int ret = 0;
    __u32 key = 0;
    char comm[16];

    // Get the process name for debugging context
    bpf_get_current_comm(&comm, sizeof(comm));

    // Filter: Only care about BPF_PROG_LOAD
    if (cmd != BPF_PROG_LOAD) {
        // Optional: comment this out if it's too noisy
        // bpf_printk("VerityGate: [%s] Ignoring cmd %d\n", comm, cmd);
        return 0;
    }

    bpf_printk("VerityGate: [%s] Intercepting BPF_PROG_LOAD\n", comm);

    // Filter: Allow signed programs (if applicable logic applies)
    if (attr->signature) {
        bpf_printk("VerityGate: [%s] Allowed (Signature present)\n", comm);
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        bpf_printk("VerityGate: [%s] ERROR: Failed to get task struct\n", comm);
        return -EPERM;
    }

    exe_file = bpf_get_task_exe_file(task);
    if (!exe_file) {
        bpf_printk("VerityGate: [%s] ERROR: Failed to get exe_file (no binary backing?)\n", comm);
        return -EPERM;
    }

    trusted_digest = bpf_map_lookup_elem(&allowed_root_hash, &key);
    if (!trusted_digest) {
        bpf_printk("VerityGate: [%s] ERROR: Map lookup failed (Trusted digest not set)\n", comm);
        bpf_put_file(exe_file);
        return -EPERM;
    }

    // Perform the DM-Verity Check
    ret = bpf_verify_dm_verity_digest(exe_file, trusted_digest, 32);

    if (ret != 0) {
        bpf_printk("VerityGate: [%s] BLOCKED: DM-Verity check failed (err: %d)\n", comm, ret);
        ret = -EPERM;
    } else {
        bpf_printk("VerityGate: [%s] ALLOWED: DM-Verity check passed\n", comm);
    }

    bpf_put_file(exe_file);
    return ret;
}