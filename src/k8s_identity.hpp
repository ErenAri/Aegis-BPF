#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace aegis {

/// Kubernetes pod identity resolved from cgroup/container metadata.
struct K8sIdentity {
    std::string pod_name;
    std::string namespace_name;
    std::string service_account;
    std::string container_id;
    std::string node_name;
};

/// Thread-safe cache mapping container IDs to Kubernetes pod identities.
/// Populated from a JSON file written by the aegis-operator's identity resolver.
class K8sIdentityCache {
  public:
    /// Load identity mappings from a JSON file.
    /// File format: {"<containerID>": {"pod":"...","namespace":"...","serviceAccount":"..."}}
    bool load_from_file(const std::string& path);

    /// Lookup identity by container ID.
    /// Returns nullptr if not found.
    const K8sIdentity* lookup_by_container(const std::string& container_id) const;

    /// Reload mappings from the previously loaded file path.
    bool reload();

    /// Number of cached identities.
    size_t size() const;

    /// True if we detected a Kubernetes environment (KUBERNETES_SERVICE_HOST set
    /// or identity file loaded with entries).
    bool is_kubernetes() const;

  private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, K8sIdentity> cache_;
    std::string file_path_;
    bool loaded_ = false;
    bool k8s_detected_ = false;
};

/// Parse the container ID from /proc/<pid>/cgroup.
/// Returns empty string if PID is not in a container.
std::string parse_container_id_from_proc(uint32_t pid);

/// Global singleton identity cache.
K8sIdentityCache& k8s_identity_cache();

} // namespace aegis
