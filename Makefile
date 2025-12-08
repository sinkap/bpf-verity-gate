# Variables
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/arm.*/arm/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/' | sed 's/riscv64/riscv/' | sed 's/loongarch64/loongarch/')

# Files
BPF_SRC := verity_gate.bpf.c
BPF_OBJ := verity_gate.bpf.o
SKEL_H := verity_gate.skel.h
LOADER_SRC := loader.c
LOADER_BIN := verity_gate_loader
SERVICE_FILE := verity_gate.service

# Installation Paths
DESTDIR ?=
BINDIR ?= /usr/sbin
UNITDIR ?= /etc/systemd/system

# Flags
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Get Clang system includes for BPF
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
    | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all clean install uninstall

all: $(LOADER_BIN)

# 1. Generate vmlinux.h
vmlinux.h:
	@echo "Generating vmlinux.h..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile BPF Object
$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	@echo "Compiling BPF object..."
	$(CLANG) $(BPF_CFLAGS) -I. $(CLANG_BPF_SYS_INCLUDES) -c $(BPF_SRC) -o $(BPF_OBJ)

# 3. Generate Skeleton
$(SKEL_H): $(BPF_OBJ)
	@echo "Generating skeleton..."
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL_H)

# 4. Compile Loader
$(LOADER_BIN): $(LOADER_SRC) $(SKEL_H)
	@echo "Compiling loader..."
	$(CLANG) $(CFLAGS) $(LOADER_SRC) -o $(LOADER_BIN) -lbpf -lelf

# 5. Clean
clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(LOADER_BIN) vmlinux.h

# 6. Install
install: $(LOADER_BIN)
	@echo "Installing binaries and systemd unit..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(LOADER_BIN) $(DESTDIR)$(BINDIR)/$(LOADER_BIN)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 644 $(SERVICE_FILE) $(DESTDIR)$(UNITDIR)/$(SERVICE_FILE)
	@echo "Files installed."
	# Only reload systemd if we are installing to the live system (DESTDIR is empty)
	@if [ -z "$(DESTDIR)" ] && [ -d /run/systemd/system ]; then \
		echo "Reloading systemd and enabling service..."; \
		systemctl daemon-reload; \
		systemctl enable verity_gate; \
	else \
		echo "Skipping systemctl (DESTDIR set or systemd not running). Enable manually."; \
	fi