/*
 * AegisBPF - eBPF-based runtime security agent
 *
 * This is the top-level compilation unit. Individual hook implementations
 * are in per-module headers included below. This preserves a single BPF
 * object and skeleton while improving source organization.
 */
#include "aegis_common.h"
#include "aegis_exec.bpf.h"
#include "aegis_file.bpf.h"
#include "aegis_process.bpf.h"
#include "aegis_net.bpf.h"
#include "aegis_kernel.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
