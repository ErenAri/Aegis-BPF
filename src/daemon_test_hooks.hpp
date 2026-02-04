// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include "kernel_features.hpp"
#include "types.hpp"

namespace aegis {

class BpfState;

using ValidateConfigDirectoryPermissionsFn = Result<void> (*)(const std::string&);
using DetectKernelFeaturesFn = Result<KernelFeatures> (*)();
using BumpMemlockRlimitFn = Result<void> (*)();
using LoadBpfFn = Result<void> (*)(bool, bool, BpfState&);
using EnsureLayoutVersionFn = Result<void> (*)(BpfState&);
using SetAgentConfigFullFn = Result<void> (*)(BpfState&, const AgentConfig&);
using PopulateSurvivalAllowlistFn = Result<void> (*)(BpfState&);
using SetupAgentCgroupFn = Result<void> (*)(BpfState&);
using AttachAllFn = Result<void> (*)(BpfState&, bool, bool, bool);

void set_validate_config_directory_permissions_for_test(ValidateConfigDirectoryPermissionsFn fn);
void reset_validate_config_directory_permissions_for_test();
void set_detect_kernel_features_for_test(DetectKernelFeaturesFn fn);
void reset_detect_kernel_features_for_test();
void set_bump_memlock_rlimit_for_test(BumpMemlockRlimitFn fn);
void reset_bump_memlock_rlimit_for_test();
void set_load_bpf_for_test(LoadBpfFn fn);
void reset_load_bpf_for_test();
void set_ensure_layout_version_for_test(EnsureLayoutVersionFn fn);
void reset_ensure_layout_version_for_test();
void set_set_agent_config_full_for_test(SetAgentConfigFullFn fn);
void reset_set_agent_config_full_for_test();
void set_populate_survival_allowlist_for_test(PopulateSurvivalAllowlistFn fn);
void reset_populate_survival_allowlist_for_test();
void set_setup_agent_cgroup_for_test(SetupAgentCgroupFn fn);
void reset_setup_agent_cgroup_for_test();
void set_attach_all_for_test(AttachAllFn fn);
void reset_attach_all_for_test();

}  // namespace aegis
