#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

#define SHA256_DIGEST_SIZE 32
#define MAX_SIG_SIZE 4096
#define MAGIC_SIZE 8

/* Standard xattr name used by fsverity tools and our bpf-trust script */
#define XATTR_NAME "user.sig"

/* Populated by the userspace loader with the Keyring ID */
__u32 verification_key_serial = 0;

/* Trusted DM-verity root hash (if using DM instead of FS verity) */
__u8 trusted_dm_digest[SHA256_DIGEST_SIZE] = {0};

struct scratch_buffer {
	/* * FIXED LAYOUT (Matches fsverity_formatted_digest):
	 * 1. Magic (8 bytes) - "FSVerity"
	 * 2. Header (4 bytes) - struct fsverity_digest (algo + size)
	 * 3. Hash Buffer (32 bytes)
	 * ---------------------------------------------------------
	 * Total Signed Data Size: 44 bytes
	 */
	__u8 magic[MAGIC_SIZE];
	struct fsverity_digest verity_header;
	__u8 digest_buffer[SHA256_DIGEST_SIZE];

	/* Signature storage */
	__u8 sig[MAX_SIG_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch_buffer);
} scratch_map SEC(".maps");

extern int bpf_get_dm_verity_digest(struct file *file,
									struct bpf_dynptr *digest_p) __ksym __weak;

SEC("lsm.s/bpf")
int BPF_PROG(verity_gate, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct file *exe_file;
	struct scratch_buffer *buf;
	struct bpf_key *trusted_keyring = NULL;
	struct bpf_dynptr data_ptr, sig_ptr;
	char comm[16];
	int ret = -EPERM;
	__u32 zero = 0;
	int i;

	/* Only intercept BPF loading operations */
	if (cmd != BPF_PROG_LOAD)
		return 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	/* Allow BPF programs that are themselves signed (Recursive Trust) */
	if (attr->signature)
		return 0;

	/* Setup Scratch Buffer */
	buf = bpf_map_lookup_elem(&scratch_map, &zero);
	if (!buf)
		return -ENOMEM;

	struct task_struct *task = bpf_get_current_task_btf();
	if (!task)
		return -EPERM;

	/* Get the binary executing the BPF load */
	exe_file = bpf_get_task_exe_file(task);
	if (!exe_file) {
		bpf_printk("VerityGate: [%s] BLOCKED: No backing binary\n", comm);
		return -EPERM;
	}

	/* Prepare Buffer with "FSVerity" Magic
	 * The kernel expects the signed data to start with these 8 bytes.
	 */
	__builtin_memcpy(buf->magic, "FSVerity", MAGIC_SIZE);

	/* check raw block hash against trusted_dm_digest */
	if (trusted_dm_digest[0] != 0) {
		bpf_dynptr_from_mem(buf->digest_buffer, SHA256_DIGEST_SIZE, 0,
							&data_ptr);
		ret = bpf_get_dm_verity_digest(exe_file, &data_ptr);

		if (ret == 0) {
			bool match = true;
			for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
				if (buf->digest_buffer[i] != trusted_dm_digest[i]) {
					match = false;
					break;
				}
			}
			if (match) {
				bpf_printk("VerityGate: [%s] ALLOWED: DM-Verity Match\n", comm);
				ret = 0;
				goto out;
			}
		}
	}

	/* We populate the buffer *after* the magic bytes.
	 * bpf_get_fsverity_digest writes: [AlgoID (2)][Size (2)][Digest (32)]
	 */
	bpf_dynptr_from_mem(&buf->verity_header,
						sizeof(struct fsverity_digest) + SHA256_DIGEST_SIZE, 0,
						&data_ptr);

	ret = bpf_get_fsverity_digest(exe_file, &data_ptr);

	if (ret < 0) {
		bpf_printk("VerityGate: [%s] BLOCKED: No Verity Metadata (err: %d)\n",
				   comm, ret);
		ret = -EPERM;
		goto out;
	}

	/* Fetch the "user.sig" xattr which contains the PKCS#7 detached sig */
	bpf_dynptr_from_mem(buf->sig, MAX_SIG_SIZE, 0, &sig_ptr);
	int xattr_len = bpf_get_file_xattr(exe_file, XATTR_NAME, &sig_ptr);

	if (xattr_len <= 0) {
		bpf_printk("VerityGate: [%s] BLOCKED: Missing Xattr %s\n", comm,
				   XATTR_NAME);
		ret = -EPERM;
		goto out;
	}

	/* Resize dynptr to actual signature length for the verifier */
	__u32 sig_len = (__u32)xattr_len;
	if (sig_len > MAX_SIG_SIZE)
		sig_len = MAX_SIG_SIZE;
	bpf_dynptr_from_mem(buf->sig, sig_len, 0, &sig_ptr);

	/* strictly enforce that a valid keyring ID was passed by userspace */
	if (verification_key_serial == 0) {
		bpf_printk("VerityGate: [%s] FATAL: Keyring ID not configured\n", comm);
		ret = -EPERM;
		goto out;
	}

	/* Look up the Keyring (key here is a misnomer, it's actually keyring)*/
	trusted_keyring = bpf_lookup_user_key(verification_key_serial, 0);

	if (!trusted_keyring) {
		bpf_printk("VerityGate: [%s] ERROR: Keyring lookup failed (ID: %d)\n",
				   comm, verification_key_serial);
		ret = -ENOENT;
		goto out;
	}

	/* We pass the Whole Buffer: [Magic] + [Header] + [Digest] */
	bpf_dynptr_from_mem(buf->magic,
						MAGIC_SIZE + sizeof(struct fsverity_digest) +
							SHA256_DIGEST_SIZE,
						0, &data_ptr);

	ret = bpf_verify_pkcs7_signature(&data_ptr, &sig_ptr, trusted_keyring);

	if (ret == 0) {
		bpf_printk("VerityGate: [%s] ALLOWED: Signature Verified\n", comm);
	} else {
		bpf_printk("VerityGate: [%s] BLOCKED: Bad Signature (err: %d)\n", comm,
				   ret);
		ret = -EPERM;
	}

out:
	if (trusted_keyring)
		bpf_key_put(trusted_keyring);
	bpf_put_file(exe_file);
	return ret;
}