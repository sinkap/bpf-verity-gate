#include "verity_gate.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

#define HASH_SIZE 32
#define PIN_PATH "/sys/fs/bpf/verity_gate"

static int hex_str_to_bytes(const char *hex, __u8 *bytes, int max_len)
{
	unsigned int temp;
	int len;
	int i;

	len = strlen(hex);
	if (len % 2 != 0 || (len / 2) > max_len)
		return -1;

	for (i = 0; i < len / 2; i++) {
		if (sscanf(&hex[i * 2], "%2x", &temp) != 1)
			return -1;
		bytes[i] = (__u8)temp;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct verity_gate_bpf *skel = NULL;
	__u8 trusted_hash[HASH_SIZE] = {0};
	char link_path[PATH_MAX];
	int map_fd;
	int key = 0;
	int err;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <roothash>\n", argv[0]);
		return 1;
	}

	if (access(PIN_PATH, F_OK) == 0) {
		printf("VerityGate: Object already pinned at %s\n", PIN_PATH);
		return 0;
	}

	if (hex_str_to_bytes(argv[1], trusted_hash, HASH_SIZE) != 0) {
		fprintf(stderr, "VerityGate: Invalid roothash format\n");
		return 1;
	}

	skel = verity_gate_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "VerityGate: Failed to open and load BPF\n");
		return 1;
	}

	map_fd = bpf_map__fd(skel->maps.allowed_root_hash);
	if (map_fd < 0) {
		fprintf(stderr, "VerityGate: Failed to get map FD\n");
		err = -1;
		goto cleanup;
	}

	err = bpf_map_update_elem(map_fd, &key, trusted_hash, BPF_ANY);
	if (err) {
		fprintf(stderr, "VerityGate: Failed to update map: %d\n", err);
		goto cleanup;
	}

	err = verity_gate_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "VerityGate: Failed to attach BPF: %d\n", err);
		goto cleanup;
	}

	err = bpf_object__pin(skel->obj, PIN_PATH);
	if (err) {
		fprintf(stderr, "VerityGate: Failed to pin object: %d\n", err);
		goto cleanup;
	}

	snprintf(link_path, sizeof(link_path), "%s/link", PIN_PATH);

	if (!skel->links.verity_gate) {
		fprintf(stderr, "VerityGate: Link not found\n");
		err = -1;
		goto cleanup;
	}

	err = bpf_link__pin(skel->links.verity_gate, link_path);
	if (err) {
		fprintf(stderr, "VerityGate: Failed to pin link: %d\n", err);
		bpf_object__unpin(skel->obj, PIN_PATH);
		goto cleanup;
	}

	printf("VerityGate: Success\n");
	verity_gate_bpf__destroy(skel);
	return 0;

cleanup:
	verity_gate_bpf__destroy(skel);
	return -err;
}
