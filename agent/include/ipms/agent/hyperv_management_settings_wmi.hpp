#pragma once

#include "ipms/agent/hyperv_management.hpp"
#include "ipms/agent/hyperv_management_wmi.hpp"

namespace ipms::agent::windows {

enum class settings_provider_method { modify_system, modify_resource };

struct prepared_hyperv_settings {
  settings_provider_method method{settings_provider_method::modify_system};
  std::wstring service_path;
  management_wmi::ComPtr<IWbemClassObject> input;
  std::string error;
};

// Builds one fixed local provider input by cloning the currently associated
// settings object. It has no provider invocation or filesystem side effects.
prepared_hyperv_settings prepare_hyperv_settings(
    IWbemServices* services, const hyperv_management_command& command,
    management_wmi::deadline_type deadline);

}  // namespace ipms::agent::windows
