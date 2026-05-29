// SPDX-License-Identifier: GPL-2.0
//
// Event export for aegis-next: JSONL file writer for arena events.
//
// P3.4 of the prototype roadmap. Ringbuf alerts trigger a JSONL line
// write with full node context from the arena. The file rotates when
// it exceeds a configured size.

#pragma once

#include <arpa/inet.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

#include "aegis_next_prov.hpp"
#include "prov_arena_types.h"

namespace aegis_next {

class EventExporter {
public:
    // max_bytes: rotate when file exceeds this size (0 = no rotation).
    explicit EventExporter(const std::string& path,
                           std::size_t max_bytes = 50 * 1024 * 1024)
        : path_(path), max_bytes_(max_bytes)
    {
        fp_ = std::fopen(path.c_str(), "a");
    }

    ~EventExporter()
    {
        if (fp_)
            std::fclose(fp_);
    }

    EventExporter(const EventExporter&) = delete;
    EventExporter& operator=(const EventExporter&) = delete;

    bool is_open() const { return fp_ != nullptr; }

    // Export a single arena node as a JSONL line.
    void export_node(const struct prov_node& node, std::uint64_t slot,
                     const char* path_str, const struct net_flow* flow)
    {
        if (!fp_)
            return;

        // Timestamp as ISO 8601.
        char ts_buf[32];
        format_ts(node.ts_ns, ts_buf, sizeof(ts_buf));

        // Comm (null-safe).
        char comm[13]{};
        std::memcpy(comm, node.comm, 12);

        std::fprintf(fp_,
            "{\"ts\":\"%s\",\"slot\":%lu,\"kind\":\"%s\","
            "\"pid\":%u,\"ppid\":%u,\"tgid\":%u,\"uid\":%u,"
            "\"cgid\":%lu,\"comm\":\"%s\"",
            ts_buf,
            (unsigned long)slot,
            kind_name(node.kind),
            node.pid, node.ppid, node.tgid, node.uid,
            (unsigned long)node.cgid,
            comm);

        if (node.mnt_ns || node.pid_ns) {
            std::fprintf(fp_, ",\"mnt_ns\":%u,\"pid_ns\":%u",
                         node.mnt_ns, node.pid_ns);
        }

        if (path_str && path_str[0] != '\0') {
            // Escape quotes in path for valid JSON.
            std::fprintf(fp_, ",\"path\":\"");
            for (const char* p = path_str; *p; ++p) {
                if (*p == '"')
                    std::fputs("\\\"", fp_);
                else if (*p == '\\')
                    std::fputs("\\\\", fp_);
                else
                    std::fputc(*p, fp_);
            }
            std::fputc('"', fp_);
        }

        if (flow) {
            char src[INET6_ADDRSTRLEN]{};
            char dst[INET6_ADDRSTRLEN]{};
            if (flow->family == 2) { // AF_INET
                inet_ntop(AF_INET, &flow->src_v4, src, sizeof(src));
                inet_ntop(AF_INET, &flow->dst_v4, dst, sizeof(dst));
            } else if (flow->family == 10) { // AF_INET6
                inet_ntop(AF_INET6, flow->src_v6, src, sizeof(src));
                inet_ntop(AF_INET6, flow->dst_v6, dst, sizeof(dst));
            }
            std::fprintf(fp_,
                ",\"net\":{\"proto\":%u,\"src\":\"%s\",\"src_port\":%u,"
                "\"dst\":\"%s\",\"dst_port\":%u}",
                flow->proto, src, flow->src_port, dst, flow->dst_port);
        }

        std::fprintf(fp_, "}\n");
        std::fflush(fp_);
        ++count_;

        maybe_rotate();
    }

    // Export a single arena node in OCSF v1.1 format (Process Activity / class_uid 1007).
    // Maps aegis-next event kinds to OCSF activity_id and category_uid.
    void export_node_ocsf(const struct prov_node& node, std::uint64_t /*slot*/,
                          const char* path_str, const struct net_flow* flow)
    {
        if (!fp_)
            return;

        char ts_buf[32];
        format_ts(node.ts_ns, ts_buf, sizeof(ts_buf));

        char comm[13]{};
        std::memcpy(comm, node.comm, 12);

        // OCSF class_uid mapping:
        //   1007 = Process Activity (exec, fork, setuid, ptrace)
        //   4001 = Network Activity (conn, bind, listen, sendmsg)
        //   1001 = File Activity (file_open, fperm, mmap, rename, unlink)
        //   2001 = Kernel Activity (kmod)
        int class_uid = 1007;
        int activity_id = 0; // 0=Unknown
        int severity_id = 1; // 1=Informational
        const char* activity_name = "Unknown";
        const char* category_name = "System Activity";
        int category_uid = 1;

        switch (node.kind) {
        case PROV_KIND_EXEC:
            class_uid = 1007; activity_id = 1; activity_name = "Launch";
            break;
        case PROV_KIND_TASK_ALLOC:
            class_uid = 1007; activity_id = 1; activity_name = "Fork";
            break;
        case PROV_KIND_SETUID:
            class_uid = 1007; activity_id = 5; activity_name = "Set User ID";
            severity_id = 3; // High
            break;
        case PROV_KIND_PTRACE:
            class_uid = 1007; activity_id = 99; activity_name = "Ptrace";
            severity_id = 4; // Critical
            break;
        case PROV_KIND_FILE_OPEN:
            class_uid = 1001; activity_id = 1; activity_name = "Open";
            category_name = "File Activity"; category_uid = 1;
            break;
        case PROV_KIND_FILE_PERM:
            class_uid = 1001; activity_id = 6; activity_name = "Permission Check";
            category_name = "File Activity"; category_uid = 1;
            break;
        case PROV_KIND_MMAP_FILE:
            class_uid = 1001; activity_id = 99; activity_name = "Memory Map";
            category_name = "File Activity"; category_uid = 1;
            break;
        case PROV_KIND_RENAME:
            class_uid = 1001; activity_id = 5; activity_name = "Rename";
            category_name = "File Activity"; category_uid = 1;
            break;
        case PROV_KIND_UNLINK:
            class_uid = 1001; activity_id = 2; activity_name = "Delete";
            category_name = "File Activity"; category_uid = 1;
            severity_id = 2; // Low
            break;
        case PROV_KIND_SOCKET_CONNECT:
            class_uid = 4001; activity_id = 1; activity_name = "Connect";
            category_name = "Network Activity"; category_uid = 4;
            break;
        case PROV_KIND_SOCKET_BIND:
            class_uid = 4001; activity_id = 2; activity_name = "Bind";
            category_name = "Network Activity"; category_uid = 4;
            break;
        case PROV_KIND_SOCKET_LISTEN:
            class_uid = 4001; activity_id = 3; activity_name = "Listen";
            category_name = "Network Activity"; category_uid = 4;
            break;
        case PROV_KIND_SENDMSG:
            class_uid = 4001; activity_id = 4; activity_name = "Send";
            category_name = "Network Activity"; category_uid = 4;
            break;
        case PROV_KIND_KMOD_REQ:
            class_uid = 1007; activity_id = 99; activity_name = "Kernel Module Load";
            severity_id = 4;
            break;
        }

        std::fprintf(fp_,
            "{\"class_uid\":%d,\"category_uid\":%d,\"category_name\":\"%s\","
            "\"activity_id\":%d,\"activity_name\":\"%s\","
            "\"severity_id\":%d,\"time\":\"%s\","
            "\"metadata\":{\"product\":{\"name\":\"aegis-next\",\"vendor_name\":\"AegisBPF\","
            "\"version\":\"0.6.0\"},\"version\":\"1.1.0\"},"
            "\"actor\":{\"process\":{\"pid\":%u,\"uid\":%u,"
            "\"name\":\"%s\",\"parent_process\":{\"pid\":%u}}}",
            class_uid, category_uid, category_name,
            activity_id, activity_name,
            severity_id, ts_buf,
            node.tgid, node.uid, comm, node.ppid);

        if (node.cgid) {
            std::fprintf(fp_, ",\"container\":{\"uid\":\"%lu\"}",
                         (unsigned long)node.cgid);
        }

        if (path_str && path_str[0] != '\0') {
            std::fprintf(fp_, ",\"file\":{\"path\":\"");
            for (const char* p = path_str; *p; ++p) {
                if (*p == '"') std::fputs("\\\"", fp_);
                else if (*p == '\\') std::fputs("\\\\", fp_);
                else std::fputc(*p, fp_);
            }
            std::fputs("\"}", fp_);
        }

        if (flow) {
            char src[INET6_ADDRSTRLEN]{};
            char dst[INET6_ADDRSTRLEN]{};
            if (flow->family == 2) {
                inet_ntop(AF_INET, &flow->src_v4, src, sizeof(src));
                inet_ntop(AF_INET, &flow->dst_v4, dst, sizeof(dst));
            } else if (flow->family == 10) {
                inet_ntop(AF_INET6, flow->src_v6, src, sizeof(src));
                inet_ntop(AF_INET6, flow->dst_v6, dst, sizeof(dst));
            }
            std::fprintf(fp_,
                ",\"src_endpoint\":{\"ip\":\"%s\",\"port\":%u},"
                "\"dst_endpoint\":{\"ip\":\"%s\",\"port\":%u}",
                src, flow->src_port, dst, flow->dst_port);
        }

        std::fprintf(fp_, "}\n");
        std::fflush(fp_);
        ++count_;
        maybe_rotate();
    }

    std::uint64_t count() const { return count_; }

private:
    std::string path_;
    std::size_t max_bytes_;
    FILE* fp_ = nullptr;
    std::uint64_t count_ = 0;

    static void format_ts(std::uint64_t ns, char* buf, std::size_t bufsz)
    {
        std::time_t sec = static_cast<std::time_t>(ns / 1000000000ULL);
        unsigned ms = static_cast<unsigned>((ns / 1000000ULL) % 1000);
        struct tm tm{};
        gmtime_r(&sec, &tm);
        int n = std::snprintf(buf, bufsz,
                              "%04d-%02d-%02dT%02d:%02d:%02d.%03uZ",
                              tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                              tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
        if (n < 0 || static_cast<std::size_t>(n) >= bufsz)
            buf[0] = '\0';
    }

    void maybe_rotate()
    {
        if (max_bytes_ == 0)
            return;
        long pos = std::ftell(fp_);
        if (pos < 0 || static_cast<std::size_t>(pos) < max_bytes_)
            return;

        std::fclose(fp_);

        // Rotate: current → .1, .1 → .2, etc. Keep 3 rotations.
        for (int i = 2; i >= 0; --i) {
            std::string from = (i == 0) ? path_
                                        : path_ + "." + std::to_string(i);
            std::string to = path_ + "." + std::to_string(i + 1);
            std::rename(from.c_str(), to.c_str());
        }

        fp_ = std::fopen(path_.c_str(), "w");
    }
};

} // namespace aegis_next
