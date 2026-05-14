// SPDX-License-Identifier: GPL-2.0
//
// Shared constants between BPF and userspace for the aegis-next
// provenance graph. This header is valid C (not C++), uses no
// kernel types, and is included by both provenance.bpf.c and
// aegis_next_prov.hpp.

#ifndef AEGIS_NEXT_PROV_TYPES_H
#define AEGIS_NEXT_PROV_TYPES_H

// Event kind stored in prov_node.kind.
#define PROV_KIND_EXEC            0
#define PROV_KIND_FILE_OPEN       1
#define PROV_KIND_SOCKET_CONNECT  2

// prov_node.extra interpretation per kind:
//   EXEC:           0 (unused)
//   FILE_OPEN:      open flags (O_RDONLY, O_WRONLY, ...)
//   SOCKET_CONNECT: address family (AF_INET, AF_INET6, ...)

#endif // AEGIS_NEXT_PROV_TYPES_H
