#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

struct bpf_dynptr;

extern int bpf_get_dm_verity_digest(struct file *file, struct bpf_dynptr *digest_p) __ksym;
extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
extern void bpf_put_file(struct file *file) __ksym;

#define DIGEST_SIZE 32
__u8 current_digest[DIGEST_SIZE] = {0};
__u8 trusted_digest[DIGEST_SIZE] = {0};

/**
 * BPF_PROG(verity_gate) - LSM hook for BPF program loading.
 *
 * Intercepts BPF program load requests and verifies the executable file
 * (the process attempting to load BPF) against a trusted dm-verity hash.
 *
 * @cmd: The BPF command being executed.
 * @attr: Attributes for the command.
 * @size: Size of the attributes struct.
 *
 * Return: 0 to allow the operation, or a negative error code (e.g., -EPERM) to block.
 */
SEC("lsm.s/bpf")
int BPF_PROG(verity_gate, int cmd, union bpf_attr *attr, unsigned int size)
{
    struct file *exe_file;
    int ret = 0;
    __u32 key = 0;
    char comm[16];
    struct bpf_dynptr digest_dynptr;
    const __u32 digest_size = DIGEST_SIZE;
    __u32 i;
    int cmp_ret = 0;

    bpf_get_current_comm(&comm, sizeof(comm));

    if (cmd != BPF_PROG_LOAD)
        return 0;

    bpf_printk("VerityGate: [%s] Intercepting BPF_PROG_LOAD\n", comm);

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

    ret = bpf_dynptr_from_mem(current_digest, digest_size, 0, &digest_dynptr);
    if (ret) {
        bpf_printk("VerityGate: [%s] ERROR: Dynptr init failed (err: %d)\n", comm, ret);
        ret = -EPERM;
        goto out_put_file;
    }

    ret = bpf_get_dm_verity_digest(exe_file, &digest_dynptr);
    if (ret != 0) {
        bpf_printk("VerityGate: [%s] BLOCKED: Get digest failed (err: %d)\n", comm, ret);
        ret = -EPERM;
        goto out_put_file;
    }

    for (i = 0; i < digest_size; i++) {
        if (current_digest[i] != trusted_digest[i]) {
            cmp_ret = 1;
            break;
        }
    }

    ret = cmp_ret;
    if (ret != 0) {
        bpf_printk("VerityGate: [%s] BLOCKED: DM-Verity hash MISMATCH (cmp ret: %d)\n", comm, ret);
        ret = -EPERM;
    } else {
        bpf_printk("VerityGate: [%s] ALLOWED: DM-Verity hash match\n", comm);
        ret = 0;
    }

out_put_file:
    bpf_put_file(exe_file);
    return ret;
}