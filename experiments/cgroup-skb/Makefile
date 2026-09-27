# EXPERIMENT (#323). Deliberately standalone: not wired into the top-level
# CMake build, so the prototype cannot end up in a release artifact by
# accident and can be deleted in one `rm -rf`.
CLANG   ?= clang
CC      ?= cc
VMLINUX ?= ../../build/vmlinux.h
CFLAGS  ?= -O2 -Wall -Wextra

all: aegis_cgroup_skb.bpf.o skb_probe

$(VMLINUX):
	@echo "vmlinux.h not found at $(VMLINUX); generating from kernel BTF"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

aegis_cgroup_skb.bpf.o: aegis_cgroup_skb.bpf.c
	@test -f $(VMLINUX) || $(MAKE) $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I$(dir $(VMLINUX)) -I. -c $< -o $@

skb_probe: skb_probe.c
	$(CC) $(CFLAGS) -o $@ $< -lbpf

clean:
	rm -f aegis_cgroup_skb.bpf.o skb_probe vmlinux.h *.json

.PHONY: all clean
