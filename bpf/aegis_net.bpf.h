#pragma once
/*
 * AegisBPF - Network hook implementations
 *
 * LSM hooks for network access control:
 *   - handle_socket_connect (LSM)
 *   - handle_socket_bind (LSM)
 *   - handle_socket_listen (LSM)
 *   - handle_socket_accept (LSM)
 *   - handle_socket_sendmsg (LSM)
 *   - handle_socket_recvmsg (LSM)
 */

/* ============================================================================
 * Network LSM Hooks
 * ============================================================================ */

SEC("lsm/socket_connect")
int BPF_PROG(handle_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    __u64 _start_ns = bpf_ktime_get_ns();
    if (!sock || !address) {
        record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
        return 0;
    }
    (void)addrlen;

    __u8 exec_flags = agent_cfg.exec_identity_flags;
    if (agent_cfg.net_policy_empty && !(exec_flags & EXEC_IDENTITY_FLAG_PROTECT_CONNECT)) {
        record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
        return 0;
    }

    __u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family)) {
        /* Fail-open on parse error: never deny a syscall because we
         * couldn't read the sockaddr.  This matches file-hook behavior
         * and avoids denying legitimate traffic on kernel edge cases. */
        record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
        return 0;
    }

    if (family != AF_INET && family != AF_INET6) {
        record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
        return 0;
    }

    __be32 remote_ip_v4 = 0;
    struct ipv6_key remote_ip_v6 = {};
    __u16 remote_port = 0;
    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_kernel(&sin, sizeof(sin), address)) {
            record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
            return 0;  /* fail-open on parse error */
        }
        remote_ip_v4 = sin.sin_addr.s_addr;
        remote_port = bpf_ntohs(sin.sin_port);
    } else {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_kernel(&sin6, sizeof(sin6), address)) {
            record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
            return 0;  /* fail-open on parse error */
        }
        remote_port = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(remote_ip_v6.addr, &sin6.sin6_addr, sizeof(remote_ip_v6.addr));
    }

    /* Get socket protocol */
    __u8 protocol = BPF_CORE_READ(sock, sk, sk_protocol);

    int matched = 0;
    char rule_type[16] = {};

    if ((exec_flags & EXEC_IDENTITY_FLAG_PROTECT_CONNECT)) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct task_struct *task = bpf_get_current_task_btf();
        struct process_info *pi = get_or_create_process_info(pid, task);
        __u8 verified = (pi && pi->exec_identity_known && pi->verified_exec) ? 1 : 0;
        if (!verified) {
            matched = 1;
            __builtin_memcpy(rule_type, "identity", sizeof("identity"));
        }
    }

    if (family == AF_INET) {
        /* Check 1: Exact IPv4+port match */
        if (!matched && ip_port_rule_matches_v4(remote_ip_v4, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
            increment_net_ip_stat_v4(remote_ip_v4);
            increment_net_port_stat(remote_port);
        }

        /* Check 2: Exact IPv4 match */
        if (!matched && bpf_map_lookup_elem(&deny_ipv4, &remote_ip_v4)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v4(remote_ip_v4);
        }

        /* Check 3: IPv4 CIDR match via LPM trie */
        if (!matched) {
            struct ipv4_lpm_key lpm_key = {
                .prefixlen = 32,
                .addr = remote_ip_v4,
            };
            if (bpf_map_lookup_elem(&deny_cidr_v4, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v4(remote_ip_v4);
            }
        }
    } else {
        /* Check 1: Exact IPv6+port match */
        if (!matched && ip_port_rule_matches_v6(&remote_ip_v6, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
            increment_net_ip_stat_v6(&remote_ip_v6);
            increment_net_port_stat(remote_port);
        }

        /* Check 2: Exact IPv6 match */
        if (!matched && bpf_map_lookup_elem(&deny_ipv6, &remote_ip_v6)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v6(&remote_ip_v6);
        }

        /* Check 3: IPv6 CIDR match via LPM trie */
        if (!matched) {
            struct ipv6_lpm_key lpm_key = {
                .prefixlen = 128,
                .addr = {0},
            };
            __builtin_memcpy(lpm_key.addr, remote_ip_v6.addr, sizeof(lpm_key.addr));
            if (bpf_map_lookup_elem(&deny_cidr_v6, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v6(&remote_ip_v6);
            }
        }
    }

    /* Check 4: Port match (protocol/direction aware) */
    if (!matched) {
        if (port_rule_matches(remote_port, protocol, 0)) {
            matched = 1;
            __builtin_memcpy(rule_type, "port", 5);
            increment_net_port_stat(remote_port);
        }
    }

    /* Check 5: Cgroup-scoped network deny (per-workload policy) */
    if (!matched && family == AF_INET && cgroup_ipv4_denied(cgid, remote_ip_v4)) {
        matched = 1;
        __builtin_memcpy(rule_type, "cg_ip", 6);
        increment_net_ip_stat_v4(remote_ip_v4);
    }
    if (!matched && cgroup_port_denied(cgid, remote_port, protocol, 0)) {
        matched = 1;
        __builtin_memcpy(rule_type, "cg_port", 8);
        increment_net_port_stat(remote_port);
    }

    if (!matched) {
        record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
        return 0;
    }

    /* Rule matched - process denial (audit logs + allows; enforce denies). */
    __u8 audit = get_effective_audit_mode();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;
    __u8 enforce_signal = audit ? 0 : compute_net_enforce_signal(pid, start_time);

    /* Update global network block stats */
    increment_net_connect_stats();
    increment_cgroup_stat(cgid);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    if (should_emit_event(get_event_sample_rate())) {
        emit_net_block_event(EVENT_NET_CONNECT_BLOCK, pid, task, cgid, family, protocol, 0 /*local_port*/,
                             remote_port, 0 /*egress*/, (family == AF_INET) ? remote_ip_v4 : 0,
                             (family == AF_INET6) ? remote_ip_v6.addr : NULL, audit, enforce_signal, rule_type);
    }

    record_hook_latency(HOOK_SOCKET_CONNECT, _start_ns);
    return audit ? 0 : -EPERM;
}

SEC("lsm/socket_bind")
int BPF_PROG(handle_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    __u64 _start_ns = bpf_ktime_get_ns();
    if (!sock || !address) {
        record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
        return 0;
    }
    (void)addrlen;

    if (agent_cfg.net_policy_empty) {
        record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
        return 0;
    }

    __u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family)) {
        record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
        return 0;  /* fail-open on parse error */
    }

    if (family != AF_INET && family != AF_INET6) {
        record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
        return 0;
    }

    /* Extract bind port */
    __u16 bind_port = 0;
    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_kernel(&sin, sizeof(sin), address)) {
            record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
            return 0;  /* fail-open on parse error */
        }
        bind_port = bpf_ntohs(sin.sin_port);
    } else {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_kernel(&sin6, sizeof(sin6), address)) {
            record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
            return 0;  /* fail-open on parse error */
        }
        bind_port = bpf_ntohs(sin6.sin6_port);
    }

    /* Get socket protocol */
    __u8 protocol = BPF_CORE_READ(sock, sk, sk_protocol);

    int matched = port_rule_matches(bind_port, protocol, 1);

    if (!matched) {
        record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
        return 0;
    }

    /* Rule matched - process denial (audit logs + allows; enforce denies). */
    char rule_type[16] = "port";
    __u8 audit = get_effective_audit_mode();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;
    __u8 enforce_signal = audit ? 0 : compute_net_enforce_signal(pid, start_time);

    /* Update statistics */
    increment_net_bind_stats();
    increment_cgroup_stat(cgid);
    increment_net_port_stat(bind_port);

    /* Optional signal in enforce mode (always deny with -EPERM). */
    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    if (should_emit_event(get_event_sample_rate())) {
        emit_net_block_event(EVENT_NET_BIND_BLOCK, pid, task, cgid, family, protocol, bind_port, 0 /*remote_port*/,
                             1 /*bind*/, 0, NULL, audit, enforce_signal, rule_type);
    }

    record_hook_latency(HOOK_SOCKET_BIND, _start_ns);
    return audit ? 0 : -EPERM;
}

SEC("lsm/socket_listen")
int BPF_PROG(handle_socket_listen, struct socket *sock, int backlog)
{
    __u64 _start_ns = bpf_ktime_get_ns();
    if (!sock) {
        record_hook_latency(HOOK_SOCKET_LISTEN, _start_ns);
        return 0;
    }
    (void)backlog;

    if (agent_cfg.net_policy_empty) {
        record_hook_latency(HOOK_SOCKET_LISTEN, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_SOCKET_LISTEN, _start_ns);
        return 0;
    }

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        record_hook_latency(HOOK_SOCKET_LISTEN, _start_ns);
        return 0;
    }

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        record_hook_latency(HOOK_SOCKET_LISTEN, _start_ns);
        return 0;
    }

    __u16 listen_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (listen_port == 0) {
        record_hook_latency(HOOK_SOCKET_LISTEN, _start_ns);
        return 0;
    }

    __u8 protocol = BPF_CORE_READ(sk, sk_protocol);

    if (!port_rule_matches(listen_port, protocol, 1)) {
        record_hook_latency(HOOK_SOCKET_LISTEN, _start_ns);
        return 0;
    }

    /* Rule matched - process denial (audit logs + allows; enforce denies). */
    char rule_type[16] = "port";
    __u8 audit = get_effective_audit_mode();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;
    __u8 enforce_signal = audit ? 0 : compute_net_enforce_signal(pid, start_time);

    increment_net_listen_stats();
    increment_cgroup_stat(cgid);
    increment_net_port_stat(listen_port);

    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    if (should_emit_event(get_event_sample_rate())) {
        emit_net_block_event(EVENT_NET_LISTEN_BLOCK, pid, task, cgid, family, protocol, listen_port, 0 /*remote_port*/,
                             2 /*listen*/, 0, NULL, audit, enforce_signal, rule_type);
    }

    record_hook_latency(HOOK_SOCKET_LISTEN, _start_ns);
    return audit ? 0 : -EPERM;
}

SEC("lsm/socket_accept")
int BPF_PROG(handle_socket_accept, struct socket *sock, struct socket *newsock)
{
    __u64 _start_ns = bpf_ktime_get_ns();
    if (!sock) {
        record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
        return 0;
    }

    if (agent_cfg.net_policy_empty) {
        record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    /* Skip allowed cgroups */
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
        return 0;
    }

    struct sock *accepted_sk = NULL;
    if (newsock)
        accepted_sk = BPF_CORE_READ(newsock, sk);
    if (!accepted_sk)
        accepted_sk = BPF_CORE_READ(sock, sk);
    if (!accepted_sk) {
        record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
        return 0;
    }

    __u16 family = BPF_CORE_READ(accepted_sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
        return 0;
    }

    __u16 accept_port = BPF_CORE_READ(accepted_sk, __sk_common.skc_num);
    if (accept_port == 0) {
        record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
        return 0;
    }

    __u8 protocol = BPF_CORE_READ(accepted_sk, sk_protocol);
    if (!port_rule_matches(accept_port, protocol, 1)) {
        record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
        return 0;
    }

    __be32 remote_ip_v4 = 0;
    struct ipv6_key remote_ip_v6 = {};
    __be16 remote_port_be = BPF_CORE_READ(accepted_sk, __sk_common.skc_dport);
    __u16 remote_port = bpf_ntohs(remote_port_be);
    if (family == AF_INET) {
        remote_ip_v4 = BPF_CORE_READ(accepted_sk, __sk_common.skc_daddr);
    } else {
        struct in6_addr remote_addr = {};
        BPF_CORE_READ_INTO(&remote_addr, accepted_sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(remote_ip_v6.addr, &remote_addr, sizeof(remote_ip_v6.addr));
    }

    int matched = 0;
    char rule_type[16] = {};

    if (family == AF_INET) {
        if (!matched && ip_port_rule_matches_v4(remote_ip_v4, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
            increment_net_ip_stat_v4(remote_ip_v4);
            increment_net_port_stat(remote_port);
        }

        if (!matched && bpf_map_lookup_elem(&deny_ipv4, &remote_ip_v4)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v4(remote_ip_v4);
        }

        if (!matched) {
            struct ipv4_lpm_key lpm_key = {
                .prefixlen = 32,
                .addr = remote_ip_v4,
            };
            if (bpf_map_lookup_elem(&deny_cidr_v4, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v4(remote_ip_v4);
            }
        }
    } else {
        if (!matched && ip_port_rule_matches_v6(&remote_ip_v6, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
            increment_net_ip_stat_v6(&remote_ip_v6);
            increment_net_port_stat(remote_port);
        }

        if (!matched && bpf_map_lookup_elem(&deny_ipv6, &remote_ip_v6)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v6(&remote_ip_v6);
        }

        if (!matched) {
            struct ipv6_lpm_key lpm_key = {
                .prefixlen = 128,
                .addr = {0},
            };
            __builtin_memcpy(lpm_key.addr, remote_ip_v6.addr, sizeof(lpm_key.addr));
            if (bpf_map_lookup_elem(&deny_cidr_v6, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v6(&remote_ip_v6);
            }
        }
    }

    if (!matched && port_rule_matches(accept_port, protocol, 1)) {
        matched = 1;
        __builtin_memcpy(rule_type, "port", 5);
        increment_net_port_stat(accept_port);
    }

    /* Cgroup-scoped network deny (per-workload policy) */
    if (!matched && family == AF_INET && cgroup_ipv4_denied(cgid, remote_ip_v4)) {
        matched = 1;
        __builtin_memcpy(rule_type, "cg_ip", 6);
        increment_net_ip_stat_v4(remote_ip_v4);
    }
    if (!matched && cgroup_port_denied(cgid, accept_port, protocol, 1)) {
        matched = 1;
        __builtin_memcpy(rule_type, "cg_port", 8);
        increment_net_port_stat(accept_port);
    }

    if (!matched) {
        record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
        return 0;
    }

    /* Rule matched - process denial (audit logs + allows; enforce denies). */
    __u8 audit = get_effective_audit_mode();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;
    __u8 enforce_signal = audit ? 0 : compute_net_enforce_signal(pid, start_time);

    increment_net_accept_stats();
    increment_cgroup_stat(cgid);

    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    if (should_emit_event(get_event_sample_rate())) {
        emit_net_block_event(EVENT_NET_ACCEPT_BLOCK, pid, task, cgid, family, protocol, accept_port, remote_port,
                             3 /*accept*/, (family == AF_INET) ? remote_ip_v4 : 0,
                             (family == AF_INET6) ? remote_ip_v6.addr : NULL, audit, enforce_signal, rule_type);
    }

    record_hook_latency(HOOK_SOCKET_ACCEPT, _start_ns);
    return audit ? 0 : -EPERM;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(handle_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    __u64 _start_ns = bpf_ktime_get_ns();
    if (!sock || !msg) {
        record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
        return 0;
    }
    (void)size;

    if (agent_cfg.net_policy_empty) {
        record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
        return 0;
    }

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
        return 0;
    }

    __u8 protocol = BPF_CORE_READ(sk, sk_protocol);
    __u16 family = 0;
    __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __be32 remote_ip_v4 = 0;
    struct ipv6_key remote_ip_v6 = {};
    __u16 remote_port = 0;

    void *msg_name = BPF_CORE_READ(msg, msg_name);
    int msg_namelen = BPF_CORE_READ(msg, msg_namelen);

    if (msg_name) {
        if (bpf_probe_read_kernel(&family, sizeof(family), msg_name)) {
            record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
            return 0;  /* fail-open on parse error */
        }

        if (family == AF_INET) {
            struct sockaddr_in sin = {};
            if (msg_namelen < (__s32)sizeof(sin)) {
                record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
                return 0;
            }
            if (bpf_probe_read_kernel(&sin, sizeof(sin), msg_name)) {
                record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
                return 0;  /* fail-open on parse error */
            }
            remote_ip_v4 = sin.sin_addr.s_addr;
            remote_port = bpf_ntohs(sin.sin_port);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sin6 = {};
            if (msg_namelen < (__s32)sizeof(sin6)) {
                record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
                return 0;
            }
            if (bpf_probe_read_kernel(&sin6, sizeof(sin6), msg_name)) {
                record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
                return 0;  /* fail-open on parse error */
            }
            remote_port = bpf_ntohs(sin6.sin6_port);
            __builtin_memcpy(remote_ip_v6.addr, &sin6.sin6_addr, sizeof(remote_ip_v6.addr));
        } else {
            record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
            return 0;
        }
    } else {
        family = BPF_CORE_READ(sk, __sk_common.skc_family);
        if (family != AF_INET && family != AF_INET6) {
            record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
            return 0;
        }

        remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        if (family == AF_INET) {
            remote_ip_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            if (remote_port == 0 || remote_ip_v4 == 0) {
                record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
                return 0;
            }
        } else {
            struct in6_addr remote_addr = {};
            BPF_CORE_READ_INTO(&remote_addr, sk, __sk_common.skc_v6_daddr);
            __builtin_memcpy(remote_ip_v6.addr, &remote_addr, sizeof(remote_ip_v6.addr));
            if (remote_port == 0) {
                record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
                return 0;
            }
        }
    }

    int matched = 0;
    char rule_type[16] = {};

    if (family == AF_INET) {
        if (!matched && ip_port_rule_matches_v4(remote_ip_v4, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
            increment_net_ip_stat_v4(remote_ip_v4);
            increment_net_port_stat(remote_port);
        }

        if (!matched && bpf_map_lookup_elem(&deny_ipv4, &remote_ip_v4)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v4(remote_ip_v4);
        }

        if (!matched) {
            struct ipv4_lpm_key lpm_key = {
                .prefixlen = 32,
                .addr = remote_ip_v4,
            };
            if (bpf_map_lookup_elem(&deny_cidr_v4, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v4(remote_ip_v4);
            }
        }
    } else {
        if (!matched && ip_port_rule_matches_v6(&remote_ip_v6, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
            increment_net_ip_stat_v6(&remote_ip_v6);
            increment_net_port_stat(remote_port);
        }

        if (!matched && bpf_map_lookup_elem(&deny_ipv6, &remote_ip_v6)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v6(&remote_ip_v6);
        }

        if (!matched) {
            struct ipv6_lpm_key lpm_key = {
                .prefixlen = 128,
                .addr = {0},
            };
            __builtin_memcpy(lpm_key.addr, remote_ip_v6.addr, sizeof(lpm_key.addr));
            if (bpf_map_lookup_elem(&deny_cidr_v6, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v6(&remote_ip_v6);
            }
        }
    }

    if (!matched && port_rule_matches(remote_port, protocol, 0)) {
        matched = 1;
        __builtin_memcpy(rule_type, "port", 5);
        increment_net_port_stat(remote_port);
    }

    /* Cgroup-scoped network deny (per-workload policy) */
    if (!matched && family == AF_INET && cgroup_ipv4_denied(cgid, remote_ip_v4)) {
        matched = 1;
        __builtin_memcpy(rule_type, "cg_ip", 6);
        increment_net_ip_stat_v4(remote_ip_v4);
    }
    if (!matched && cgroup_port_denied(cgid, remote_port, protocol, 0)) {
        matched = 1;
        __builtin_memcpy(rule_type, "cg_port", 8);
        increment_net_port_stat(remote_port);
    }

    if (!matched) {
        record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
        return 0;
    }

    /* Rule matched - process denial (audit logs + allows; enforce denies). */
    __u8 audit = get_effective_audit_mode();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;
    __u8 enforce_signal = audit ? 0 : compute_net_enforce_signal(pid, start_time);

    increment_net_sendmsg_stats();
    increment_cgroup_stat(cgid);

    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    if (should_emit_event(get_event_sample_rate())) {
        emit_net_block_event(EVENT_NET_SENDMSG_BLOCK, pid, task, cgid, family, protocol, local_port, remote_port,
                             4 /*send*/, (family == AF_INET) ? remote_ip_v4 : 0,
                             (family == AF_INET6) ? remote_ip_v6.addr : NULL, audit, enforce_signal, rule_type);
    }

    record_hook_latency(HOOK_SOCKET_SENDMSG, _start_ns);
    return audit ? 0 : -EPERM;
}

/* ============================================================================
 * socket_recvmsg - Intercept incoming data on connected sockets.
 *
 * Evaluates the peer (source) address against deny rules, enabling detection
 * and blocking of data reception from denied IPs/ports/CIDRs.  This closes
 * the last gap in socket lifecycle enforcement: even if a connection was
 * established before a deny rule was loaded, recvmsg enforcement prevents
 * further data ingress from the blocked peer.
 * ============================================================================ */
SEC("lsm/socket_recvmsg")
int BPF_PROG(handle_socket_recvmsg, struct socket *sock, struct msghdr *msg,
             int size, int flags)
{
    __u64 _start_ns = bpf_ktime_get_ns();
    if (!sock) {
        record_hook_latency(HOOK_SOCKET_RECVMSG, _start_ns);
        return 0;
    }
    (void)msg;
    (void)size;
    (void)flags;

    if (agent_cfg.net_policy_empty) {
        record_hook_latency(HOOK_SOCKET_RECVMSG, _start_ns);
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();
    if (is_cgroup_allowed(cgid)) {
        record_hook_latency(HOOK_SOCKET_RECVMSG, _start_ns);
        return 0;
    }

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        record_hook_latency(HOOK_SOCKET_RECVMSG, _start_ns);
        return 0;
    }

    __u8 protocol = BPF_CORE_READ(sk, sk_protocol);
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        record_hook_latency(HOOK_SOCKET_RECVMSG, _start_ns);
        return 0;
    }

    __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    __be32 remote_ip_v4 = 0;
    struct ipv6_key remote_ip_v6 = {};

    if (family == AF_INET) {
        remote_ip_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        if (remote_port == 0 && remote_ip_v4 == 0) {
            record_hook_latency(HOOK_SOCKET_RECVMSG, _start_ns);
            return 0;
        }
    } else {
        struct in6_addr remote_addr = {};
        BPF_CORE_READ_INTO(&remote_addr, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(remote_ip_v6.addr, &remote_addr, sizeof(remote_ip_v6.addr));
    }

    int matched = 0;
    char rule_type[16] = {};

    if (family == AF_INET) {
        if (!matched && ip_port_rule_matches_v4(remote_ip_v4, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
            increment_net_ip_stat_v4(remote_ip_v4);
            increment_net_port_stat(remote_port);
        }

        if (!matched && bpf_map_lookup_elem(&deny_ipv4, &remote_ip_v4)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v4(remote_ip_v4);
        }

        if (!matched) {
            struct ipv4_lpm_key lpm_key = {
                .prefixlen = 32,
                .addr = remote_ip_v4,
            };
            if (bpf_map_lookup_elem(&deny_cidr_v4, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v4(remote_ip_v4);
            }
        }
    } else {
        if (!matched && ip_port_rule_matches_v6(&remote_ip_v6, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
            increment_net_ip_stat_v6(&remote_ip_v6);
            increment_net_port_stat(remote_port);
        }

        if (!matched && bpf_map_lookup_elem(&deny_ipv6, &remote_ip_v6)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
            increment_net_ip_stat_v6(&remote_ip_v6);
        }

        if (!matched) {
            struct ipv6_lpm_key lpm_key = {
                .prefixlen = 128,
                .addr = {0},
            };
            __builtin_memcpy(lpm_key.addr, remote_ip_v6.addr, sizeof(lpm_key.addr));
            if (bpf_map_lookup_elem(&deny_cidr_v6, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
                increment_net_ip_stat_v6(&remote_ip_v6);
            }
        }
    }

    /* For recvmsg, check port rules with direction=0 (egress/peer-facing) since
     * we are evaluating the remote peer's port, not a local bind port. */
    if (!matched && port_rule_matches(remote_port, protocol, 0)) {
        matched = 1;
        __builtin_memcpy(rule_type, "port", 5);
        increment_net_port_stat(remote_port);
    }

    if (!matched) {
        record_hook_latency(HOOK_SOCKET_RECVMSG, _start_ns);
        return 0;
    }

    /* Rule matched - process denial (audit logs + allows; enforce denies). */
    __u8 audit = get_effective_audit_mode();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;
    __u8 enforce_signal = audit ? 0 : compute_net_enforce_signal(pid, start_time);

    increment_net_recvmsg_stats();
    increment_cgroup_stat(cgid);

    if (!audit) {
        maybe_send_enforce_signal(enforce_signal);
    }

    if (should_emit_event(get_event_sample_rate())) {
        emit_net_block_event(EVENT_NET_RECVMSG_BLOCK, pid, task, cgid, family, protocol, local_port, remote_port,
                             5 /*recv*/, (family == AF_INET) ? remote_ip_v4 : 0,
                             (family == AF_INET6) ? remote_ip_v6.addr : NULL, audit, enforce_signal, rule_type);
    }

    record_hook_latency(HOOK_SOCKET_RECVMSG, _start_ns);
    return audit ? 0 : -EPERM;
}

/* ============================================================================
 * Signal-fallback enforcement (Tier 3 — for kernels without BPF-LSM)
 *
 * On hosts where BPF-LSM is unavailable, lsm/socket_connect cannot attach and
 * outbound connect() cannot be denied with -EPERM. This connect() tracepoint
 * provides a weaker enforcement tier: when agent_cfg.signal_fallback_enforce is
 * set AND the agent is in enforce mode, a connect() to a denied endpoint is met
 * with bpf_send_signal(), terminating the offending process.
 *
 * This is detection + signal, NOT synchronous denial: the connect() syscall may
 * partially proceed before the signal is delivered on syscall return. The
 * program is inert unless explicitly enabled (default off), so on LSM-capable
 * hosts running normally it early-returns after a single global read.
 *
 * Protocol is unknown at syscall entry (no socket lookup), so only
 * protocol-agnostic deny rules (protocol=any) are evaluated here.
 * ============================================================================ */
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (!agent_cfg.signal_fallback_enforce)
        return 0;
    if (agent_cfg.net_policy_empty)
        return 0;

    void *uaddr = (void *)ctx->args[1];
    int addrlen = (int)ctx->args[2];
    if (!uaddr)
        return 0;

    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), uaddr))
        return 0;
    if (family != AF_INET && family != AF_INET6)
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (is_cgroup_allowed(cgid))
        return 0;

    __be32 remote_ip_v4 = 0;
    struct ipv6_key remote_ip_v6 = {};
    __u16 remote_port = 0;

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        if (addrlen < (int)sizeof(sin))
            return 0;
        if (bpf_probe_read_user(&sin, sizeof(sin), uaddr))
            return 0;
        remote_ip_v4 = sin.sin_addr.s_addr;
        remote_port = bpf_ntohs(sin.sin_port);
    } else {
        struct sockaddr_in6 sin6 = {};
        if (addrlen < (int)sizeof(sin6))
            return 0;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), uaddr))
            return 0;
        remote_port = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(remote_ip_v6.addr, &sin6.sin6_addr, sizeof(remote_ip_v6.addr));
    }

    __u8 protocol = 0; /* protocol-agnostic: socket not resolvable at entry */
    int matched = 0;
    char rule_type[16] = {};

    if (family == AF_INET) {
        if (!matched && ip_port_rule_matches_v4(remote_ip_v4, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
        }
        if (!matched && bpf_map_lookup_elem(&deny_ipv4, &remote_ip_v4)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
        }
        if (!matched) {
            struct ipv4_lpm_key lpm_key = {
                .prefixlen = 32,
                .addr = remote_ip_v4,
            };
            if (bpf_map_lookup_elem(&deny_cidr_v4, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
            }
        }
    } else {
        if (!matched && ip_port_rule_matches_v6(&remote_ip_v6, remote_port, protocol)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip_port", sizeof("ip_port"));
        }
        if (!matched && bpf_map_lookup_elem(&deny_ipv6, &remote_ip_v6)) {
            matched = 1;
            __builtin_memcpy(rule_type, "ip", 3);
        }
        if (!matched) {
            struct ipv6_lpm_key lpm_key = {
                .prefixlen = 128,
                .addr = {0},
            };
            __builtin_memcpy(lpm_key.addr, remote_ip_v6.addr, sizeof(lpm_key.addr));
            if (bpf_map_lookup_elem(&deny_cidr_v6, &lpm_key)) {
                matched = 1;
                __builtin_memcpy(rule_type, "cidr", 5);
            }
        }
    }

    if (!matched && port_rule_matches(remote_port, protocol, 0)) {
        matched = 1;
        __builtin_memcpy(rule_type, "port", 5);
    }
    if (!matched && family == AF_INET && cgroup_ipv4_denied(cgid, remote_ip_v4)) {
        matched = 1;
        __builtin_memcpy(rule_type, "cg_ip", 6);
    }
    if (!matched && cgroup_port_denied(cgid, remote_port, protocol, 0)) {
        matched = 1;
        __builtin_memcpy(rule_type, "cg_port", 8);
    }

    if (!matched)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = bpf_get_current_task_btf();
    __u8 audit = get_effective_audit_mode();

    increment_net_connect_stats();
    increment_cgroup_stat(cgid);

    __u8 enforce_signal = 0;
    if (!audit) {
        __u64 start_time = task ? BPF_CORE_READ(task, start_time) : 0;
        __u8 configured_signal = get_effective_enforce_signal();
        if (configured_signal == SIGKILL) {
            enforce_signal = runtime_enforce_signal(configured_signal, pid, start_time,
                                                    get_sigkill_escalation_threshold(),
                                                    get_sigkill_escalation_window_ns());
        } else {
            /* A tracepoint cannot return -EPERM, so a too-weak signal would let
             * the connect proceed. When no SIGKILL escalation is configured,
             * default the fallback to SIGKILL to make the tier meaningful. */
            enforce_signal = configured_signal ? configured_signal : SIGKILL;
        }
        maybe_send_enforce_signal(enforce_signal);
    }

    __u32 sample_rate = get_event_sample_rate();
    if (should_emit_event(sample_rate)) {
        emit_net_block_event(EVENT_NET_CONNECT_BLOCK, pid, task, cgid, family, protocol, 0 /*local_port*/, remote_port,
                             0 /*egress (connect)*/, (family == AF_INET) ? remote_ip_v4 : 0,
                             (family == AF_INET6) ? remote_ip_v6.addr : NULL, audit, enforce_signal, rule_type);
    }

    return 0;
}
