// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "types.hpp"

namespace aegis {

class Plugin {
  public:
    virtual ~Plugin() = default;

    [[nodiscard]] virtual std::string name() const = 0;
    [[nodiscard]] virtual std::string version() const = 0;

    virtual bool on_start() { return true; }
    virtual void on_stop() {}

    virtual bool on_exec(const ExecEvent& /*ev*/) { return true; }
    virtual bool on_block(const BlockEvent& /*ev*/) { return true; }
    virtual bool on_net_block(const NetBlockEvent& /*ev*/, uint32_t /*event_type*/) { return true; }
    virtual bool on_exec_argv(const ExecArgvEvent& /*ev*/) { return true; }
};

class PluginManager {
  public:
    PluginManager() = default;

    void register_plugin(std::shared_ptr<Plugin> plugin);
    bool unregister_plugin(const std::string& name);

    void start_all();
    void stop_all();

    void dispatch_exec(const ExecEvent& ev);
    void dispatch_block(const BlockEvent& ev);
    void dispatch_net_block(const NetBlockEvent& ev, uint32_t event_type);
    void dispatch_exec_argv(const ExecArgvEvent& ev);

    [[nodiscard]] size_t plugin_count() const;
    [[nodiscard]] std::vector<std::string> plugin_names() const;

  private:
    mutable std::mutex mu_;
    std::vector<std::shared_ptr<Plugin>> plugins_;
};

class JsonLoggerPlugin : public Plugin {
  public:
    [[nodiscard]] std::string name() const override { return "json_logger"; }
    [[nodiscard]] std::string version() const override { return "1.0.0"; }

    bool on_exec(const ExecEvent& ev) override;
    bool on_block(const BlockEvent& ev) override;
    bool on_net_block(const NetBlockEvent& ev, uint32_t event_type) override;
};

} // namespace aegis
