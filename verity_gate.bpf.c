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

    if (cmd != BPF_PROG_LOAD)
        return 0;

    if (attr->signature)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return -EPERM;

    exe_file = bpf_get_task_exe_file(task);
    if (!exe_file)
        return -EPERM;

    trusted_digest = bpf_map_lookup_elem(&allowed_root_hash, &key);
    if (!trusted_digest) {
        bpf_put_file(exe_file);
        return -EPERM;
    }

    ret = bpf_verify_dm_verity_digest(exe_file, trusted_digest, 32);
    if (ret != 0) {
        bpf_printk("BPF Blocked: Loader not verified (err: %d)\n", ret);
        ret = -EPERM;
    }

    bpf_put_file(exe_file);
    return ret;
}