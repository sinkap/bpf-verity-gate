#include "verity_gate.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HASH_SIZE 32
#define PIN_PATH "/sys/fs/bpf/verity_gate"

int find_cmdline_arg(const char *key, char *value_out, size_t out_len)
{
	FILE *fp = fopen("/proc/cmdline", "r");
	if (!fp) {
		perror("Failed to open /proc/cmdline");
		return -1;
	}

	char buf[4096];
	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);

	char *token = strtok(buf, " \t\n");
	while (token != NULL) {
		size_t key_len = strlen(key);
		if (strncmp(token, key, key_len) == 0 && token[key_len] == '=') {
			const char *val_start = token + key_len + 1;
			strncpy(value_out, val_start, out_len - 1);
			value_out[out_len - 1] = '\0';
			return 0;
		}
		token = strtok(NULL, " \t\n");
	}
	return -1;
}

int hex_str_to_bytes(const char *hex, __u8 *bytes, int max_len)
{
	int len = strlen(hex);
	if (len % 2 != 0 || (len / 2) > max_len)
		return -1;

	for (int i = 0; i < len / 2; i++) {
		unsigned int temp;
		if (sscanf(&hex[i * 2], "%2x", &temp) != 1)
			return -1;
		bytes[i] = (__u8)temp;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct verity_gate_bpf *skel;
	int err;
	char hash_str[128] = {0};
	__u8 trusted_hash[HASH_SIZE] = {0};

	if (access(PIN_PATH, F_OK) == 0) {
		return 0;
	}

	if (find_cmdline_arg("roothash", hash_str, sizeof(hash_str)) != 0) {
		fprintf(stderr, "Error: 'roothash' not found in cmdline.\n");
		return 1;
	}

	if (hex_str_to_bytes(hash_str, trusted_hash, HASH_SIZE) != 0) {
		fprintf(stderr, "Error: Invalid roothash format.\n");
		return 1;
	}

	skel = verity_gate_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = verity_gate_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF application\n");
		goto cleanup;
	}

	int key = 0;
	int map_fd = bpf_map__fd(skel->maps.allowed_root_hash);
	err = bpf_map_update_elem(map_fd, &key, trusted_hash, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update map: %d\n", err);
		goto cleanup;
	}

	err = verity_gate_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	err = bpf_link__pin(skel->links.verity_gate, PIN_PATH);
	if (err) {
		fprintf(stderr, "Failed to pin program: %d\n", err);
		goto cleanup;
	}

	return 0;

cleanup:
	verity_gate_bpf__destroy(skel);
	return -err;
}