# EXPERIMENT (#323 phase 2). Standalone on purpose: not wired into the
# top-level CMake build, so the prototype cannot reach a release artifact and
# can be removed in one `rm -rf`.
CLANG   ?= clang
CC      ?= cc
VMLINUX ?= ../../build/vmlinux.h
CFLAGS  ?= -O2 -Wall -Wextra

all: aegis_flow.bpf.o flow_probe

aegis_flow.bpf.o: aegis_flow.bpf.c
	@test -f $(VMLINUX) || { echo "need $(VMLINUX); build the project first"; exit 1; }
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(dir $(VMLINUX)) -I. -c $< -o $@

flow_probe: flow_probe.c
	$(CC) $(CFLAGS) -o $@ $< -lbpf

clean:
	rm -f aegis_flow.bpf.o flow_probe *.jsonl

.PHONY: all clean
