# Variables
CLANG ?= clang
BPFTOOL ?= bpftool

# ARCH is required by Clang to handle BPF macros (like BPF_PROG) correctly.
# It is NOT used to find the vmlinux file.
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/arm.*/arm/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/' | sed 's/riscv64/riscv/' | sed 's/loongarch64/loongarch/')

# Configuration: Point this to your kernel source root
TARGET_KERNEL ?= $(HOME)/projects/linux

# Files
BPF_SRC := verity_gate.bpf.c
BPF_OBJ := verity_gate.bpf.o
SKEL_H := verity_gate.skel.h
LOADER_SRC := loader.c
LOADER_BIN := verity_gate_loader
SERVICE_FILE := verity_gate.service
HELPER_SCRIPT := verity_gate_start

# Installation Paths
DESTDIR ?=
BINDIR ?= /usr/sbin
SCRIPTDIR ?= /usr/local/bin
UNITDIR ?= /etc/systemd/system

# Flags
CFLAGS := -g -O2 -Wall
# We pass __TARGET_ARCH_xxx so bpf_tracing.h knows which registers to access
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Get Clang system includes for BPF
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
    | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all clean install uninstall

all: $(LOADER_BIN)

# 1. Generate vmlinux.h
# Logic: Try TARGET_KERNEL/vmlinux first. If missing, warn and fallback to host /sys/kernel/btf/vmlinux.
vmlinux.h:
	@if [ -f "$(TARGET_KERNEL)/vmlinux" ]; then \
		echo "Generating vmlinux.h from target: $(TARGET_KERNEL)/vmlinux..."; \
		$(BPFTOOL) btf dump file $(TARGET_KERNEL)/vmlinux format c > vmlinux.h; \
	else \
		echo "------------------------------------------------------------------"; \
		echo "WARNING: vmlinux not found at $(TARGET_KERNEL)/vmlinux"; \
		echo "         Falling back to host system BTF (/sys/kernel/btf/vmlinux)."; \
		echo "         Ensure the host kernel matches your target environment!"; \
		echo "------------------------------------------------------------------"; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

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
	@echo "Installing binaries..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(LOADER_BIN) $(DESTDIR)$(BINDIR)/$(LOADER_BIN)

	@echo "Installing helper script..."
	install -d $(DESTDIR)$(SCRIPTDIR)
	install -m 755 $(HELPER_SCRIPT) $(DESTDIR)$(SCRIPTDIR)/$(HELPER_SCRIPT)

	@echo "Installing systemd unit..."
	install -d $(DESTDIR)$(UNITDIR)
	install -m 644 $(SERVICE_FILE) $(DESTDIR)$(UNITDIR)/$(SERVICE_FILE)

	@if [ -z "$(DESTDIR)" ] && [ -d /run/systemd/system ]; then \
		echo "Reloading systemd daemon..."; \
		systemctl daemon-reload; \
		echo "Enabling service..."; \
		systemctl enable verity_gate.service; \
	fi

# 7. Uninstall
uninstall:
	@echo "Uninstalling..."
	@if [ -z "$(DESTDIR)" ] && [ -d /run/systemd/system ]; then \
		systemctl disable verity_gate.service || true; \
		systemctl stop verity_gate.service || true; \
	fi
	rm -f $(DESTDIR)$(BINDIR)/$(LOADER_BIN)
	rm -f $(DESTDIR)$(SCRIPTDIR)/$(HELPER_SCRIPT)
	rm -f $(DESTDIR)$(UNITDIR)/$(SERVICE_FILE)
	@if [ -z "$(DESTDIR)" ] && [ -d /run/systemd/system ]; then \
		systemctl daemon-reload; \
	fi