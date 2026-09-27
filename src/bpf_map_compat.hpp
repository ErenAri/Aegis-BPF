#pragma once

// Map creation that works on every libbpf we support.
//
// bpf_map_create() and struct bpf_map_create_opts arrived in libbpf 0.7.
// Ubuntu 22.04 -- a platform docs/SUPPORT_POLICY.md commits to -- ships 0.5.0,
// where the spelling is bpf_create_map_name() / bpf_create_map_in_map(). The
// support floor does not move to suit newer code, so both spellings live here
// rather than being repeated at every call site: there were eight, and the ones
// in tests/ were missed the first time precisely because they were scattered.
//
// libbpf defines bpf_map_create_opts__last_field only when the new API exists,
// which makes it a reliable feature test.

#include <bpf/bpf.h>

namespace aegis {

inline int map_create(enum bpf_map_type type, const char* name, __u32 key_size, __u32 value_size, __u32 max_entries,
                      __u32 flags = 0)
{
#ifdef bpf_map_create_opts__last_field
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.map_flags = flags;
    return bpf_map_create(type, name, key_size, value_size, max_entries, &opts);
#else
    return bpf_create_map_name(type, name, static_cast<int>(key_size), static_cast<int>(value_size),
                               static_cast<int>(max_entries), flags);
#endif
}

// An outer map's value_size is always 4 (an inner map fd), so it is not a
// parameter: the old API does not accept one and silently disagreeing with the
// new one would be worse than not offering the knob.
inline int map_create_in_map(enum bpf_map_type type, const char* name, __u32 key_size, int inner_fd, __u32 max_entries,
                             __u32 flags = 0)
{
#ifdef bpf_map_create_opts__last_field
    struct bpf_map_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.map_flags = flags;
    opts.inner_map_fd = static_cast<__u32>(inner_fd);
    return bpf_map_create(type, name, key_size, 4, max_entries, &opts);
#else
    return bpf_create_map_in_map(type, name, static_cast<int>(key_size), inner_fd, static_cast<int>(max_entries),
                                 flags);
#endif
}

} // namespace aegis
