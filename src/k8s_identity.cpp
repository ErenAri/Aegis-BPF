#include "k8s_identity.hpp"

#include <cstdlib>
#include <fstream>
#include <regex>
#include <sstream>

#include "logging.hpp"

namespace aegis {

namespace {

/// Simple JSON string value extractor — avoids pulling in a full JSON library.
/// Finds "key": "value" and returns value.
std::string extract_json_value(const std::string& json, const std::string& key)
{
    const std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos)
        return {};

    // Find the colon after the key.
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos)
        return {};

    // Find the opening quote of the value.
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos)
        return {};

    auto end = json.find('"', pos + 1);
    if (end == std::string::npos)
        return {};

    return json.substr(pos + 1, end - pos - 1);
}

/// Parse identity cache JSON file. The format is:
/// {
///   "abc123def456...": {
///     "pod": "my-pod-xyz",
///     "namespace": "production",
///     "serviceAccount": "default",
///     "containerID": "abc123def456...",
///     "nodeName": "node-1"
///   },
///   ...
/// }
std::unordered_map<std::string, K8sIdentity> parse_identity_json(const std::string& content)
{
    std::unordered_map<std::string, K8sIdentity> result;

    // Find each top-level key (container ID) and its object value.
    size_t pos = 0;
    while (pos < content.size()) {
        // Find next key.
        auto key_start = content.find('"', pos);
        if (key_start == std::string::npos)
            break;
        auto key_end = content.find('"', key_start + 1);
        if (key_end == std::string::npos)
            break;

        std::string container_id = content.substr(key_start + 1, key_end - key_start - 1);

        // Skip non-container-ID keys (they must be hex strings >= 12 chars).
        if (container_id.size() < 12) {
            pos = key_end + 1;
            continue;
        }

        // Find the object body { ... }.
        auto obj_start = content.find('{', key_end);
        if (obj_start == std::string::npos)
            break;
        auto obj_end = content.find('}', obj_start);
        if (obj_end == std::string::npos)
            break;

        std::string obj = content.substr(obj_start, obj_end - obj_start + 1);

        K8sIdentity id;
        id.pod_name = extract_json_value(obj, "pod");
        id.namespace_name = extract_json_value(obj, "namespace");
        id.service_account = extract_json_value(obj, "serviceAccount");
        id.container_id = extract_json_value(obj, "containerID");
        id.node_name = extract_json_value(obj, "nodeName");

        if (id.container_id.empty()) {
            id.container_id = container_id;
        }

        if (!id.pod_name.empty()) {
            result[container_id] = std::move(id);
        }

        pos = obj_end + 1;
    }

    return result;
}

} // namespace

bool K8sIdentityCache::load_from_file(const std::string& path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    file_path_ = path;

    // Detect K8s environment.
    if (const char* svc = std::getenv("KUBERNETES_SERVICE_HOST"); svc && svc[0]) {
        k8s_detected_ = true;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        if (k8s_detected_) {
            LOG_WARN("K8s environment detected but identity cache not found");
        }
        return false;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();

    cache_ = parse_identity_json(content);
    loaded_ = !cache_.empty();

    if (loaded_) {
        k8s_detected_ = true;
    }

    return loaded_;
}

const K8sIdentity* K8sIdentityCache::lookup_by_container(const std::string& container_id) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(container_id);
    if (it != cache_.end()) {
        return &it->second;
    }
    return nullptr;
}

bool K8sIdentityCache::reload()
{
    if (file_path_.empty())
        return false;

    std::ifstream file(file_path_);
    if (!file.is_open())
        return false;

    std::ostringstream ss;
    ss << file.rdbuf();

    auto new_cache = parse_identity_json(ss.str());

    std::lock_guard<std::mutex> lock(mutex_);
    cache_ = std::move(new_cache);
    loaded_ = !cache_.empty();
    return loaded_;
}

size_t K8sIdentityCache::size() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

bool K8sIdentityCache::is_kubernetes() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return k8s_detected_;
}

std::string parse_container_id_from_proc(uint32_t pid)
{
    // Read /proc/<pid>/cgroup and extract container ID.
    // Container IDs are 64-hex-character strings in cgroup paths.
    std::string path = "/proc/" + std::to_string(pid) + "/cgroup";
    std::ifstream file(path);
    if (!file.is_open())
        return {};

    // Match 64 hex chars (Docker/containerd container IDs).
    static const std::regex container_id_re("[0-9a-f]{64}");

    std::string line;
    while (std::getline(file, line)) {
        std::smatch match;
        if (std::regex_search(line, match, container_id_re)) {
            return match.str();
        }
    }

    return {};
}

K8sIdentityCache& k8s_identity_cache()
{
    static K8sIdentityCache instance;
    return instance;
}

} // namespace aegis
