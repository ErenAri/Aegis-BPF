// cppcheck-suppress-file missingIncludeSystem
#include "plugin.hpp"

#include <algorithm>

#include "events.hpp"
#include "logging.hpp"

namespace aegis {

void PluginManager::register_plugin(std::shared_ptr<Plugin> plugin)
{
    std::lock_guard<std::mutex> lock(mu_);
    logger().log(SLOG_INFO("Plugin registered").field("name", plugin->name()).field("version", plugin->version()));
    plugins_.push_back(std::move(plugin));
}

bool PluginManager::unregister_plugin(const std::string& name)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = std::remove_if(plugins_.begin(), plugins_.end(),
                             [&name](const std::shared_ptr<Plugin>& p) { return p->name() == name; });
    if (it == plugins_.end())
        return false;
    plugins_.erase(it, plugins_.end());
    return true;
}

void PluginManager::start_all()
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& plugin : plugins_) {
        if (!plugin->on_start()) {
            logger().log(SLOG_WARN("Plugin failed to start").field("name", plugin->name()));
        }
    }
}

void PluginManager::stop_all()
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& plugin : plugins_) {
        plugin->on_stop();
    }
}

void PluginManager::dispatch_exec(const ExecEvent& ev)
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& plugin : plugins_) {
        if (!plugin->on_exec(ev))
            break;
    }
}

void PluginManager::dispatch_block(const BlockEvent& ev)
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& plugin : plugins_) {
        if (!plugin->on_block(ev))
            break;
    }
}

void PluginManager::dispatch_net_block(const NetBlockEvent& ev, uint32_t event_type)
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& plugin : plugins_) {
        if (!plugin->on_net_block(ev, event_type))
            break;
    }
}

void PluginManager::dispatch_exec_argv(const ExecArgvEvent& ev)
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& plugin : plugins_) {
        if (!plugin->on_exec_argv(ev))
            break;
    }
}

size_t PluginManager::plugin_count() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return plugins_.size();
}

std::vector<std::string> PluginManager::plugin_names() const
{
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<std::string> names;
    names.reserve(plugins_.size());
    for (const auto& p : plugins_) {
        names.push_back(p->name());
    }
    return names;
}

bool JsonLoggerPlugin::on_exec(const ExecEvent& ev)
{
    print_exec_event(ev);
    return true;
}

bool JsonLoggerPlugin::on_block(const BlockEvent& ev)
{
    print_block_event(ev);
    return true;
}

bool JsonLoggerPlugin::on_net_block(const NetBlockEvent& ev, uint32_t /*event_type*/)
{
    print_net_block_event(ev);
    return true;
}

} // namespace aegis
