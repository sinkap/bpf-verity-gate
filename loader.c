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

// --- Helper Functions Restored ---

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

// --- Main ---

int main(int argc, char **argv)
{
    struct verity_gate_bpf *skel = NULL;
    int err;
    char hash_str[128] = {0};
    __u8 trusted_hash[HASH_SIZE] = {0};
    char link_path[PATH_MAX];

    // 1. Idempotency Check
    if (access(PIN_PATH, F_OK) == 0) {
        printf("VerityGate: Object already pinned at %s. Exiting success.\n", PIN_PATH);
        return 0;
    }

    // 2. Retrieve Configuration (With Error Logging restored)
    if (find_cmdline_arg("roothash", hash_str, sizeof(hash_str)) != 0) {
        fprintf(stderr, "VerityGate: Error - 'roothash' not found in kernel cmdline.\n");
        return 1;
    }

    if (hex_str_to_bytes(hash_str, trusted_hash, HASH_SIZE) != 0) {
        fprintf(stderr, "VerityGate: Error - Invalid roothash format.\n");
        return 1;
    }

    // 3. Open BPF Skeleton
    skel = verity_gate_bpf__open();
    if (!skel) {
        fprintf(stderr, "VerityGate: Failed to open BPF skeleton\n");
        return 1;
    }

    // 4. Load BPF into Kernel
    err = verity_gate_bpf__load(skel);
    if (err) {
        fprintf(stderr, "VerityGate: Failed to load BPF application: %d\n", err);
        goto cleanup;
    }

    // 5. Update Map
    int key = 0;
    int map_fd = bpf_map__fd(skel->maps.allowed_root_hash);
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

    // 6. Attach to LSM Hook
    err = verity_gate_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "VerityGate: Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    // 7. Pin the Object (creates the directory)
    err = bpf_object__pin(skel->obj, PIN_PATH);
    if (err) {
        fprintf(stderr, "VerityGate: Failed to pin BPF object to %s: %d\n", PIN_PATH, err);
        goto cleanup;
    }

    // 8. Pin the Link (creates the link file inside the directory)
    snprintf(link_path, sizeof(link_path), "%s/link", PIN_PATH);

    /* IMPORTANT: Ensure `skel->links.verity_gate` matches the function name 
       in your .bpf.c file. If your BPF C function is named `my_lsm`, 
       use `skel->links.my_lsm` here.
    */
    if (!skel->links.verity_gate) {
        fprintf(stderr, "VerityGate: Link 'verity_gate' not found in skeleton.\n");
        err = -1;
        goto cleanup;
    }

    err = bpf_link__pin(skel->links.verity_gate, link_path);
    if (err) {
        fprintf(stderr, "VerityGate: Failed to pin BPF link to %s: %d\n", link_path, err);
        // Unpin object to clean up partial state
        bpf_object__unpin(skel->obj, PIN_PATH); 
        goto cleanup;
    }

    printf("VerityGate: Successfully loaded and pinned object and link to %s\n", PIN_PATH);

    verity_gate_bpf__destroy(skel);
    return 0;

cleanup:
    verity_gate_bpf__destroy(skel);
    return -err;
}