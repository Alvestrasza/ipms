#pragma once

#include <string>

namespace ipms::agent::windows {

struct hyperv_inventory_result {
  std::string status;
  std::string error;
  std::string virtual_machines_json;
};

// Collects a bounded, local, read-only Hyper-V inventory. The implementation
// uses fixed WMI v2 queries and never accepts a query or command from the
// Control Plane.
hyperv_inventory_result collect_hyperv_inventory();

struct hyperv_action_result {
  bool succeeded;
  std::string result_code;
};

// Executes one fixed local Hyper-V lifecycle operation. The Control Plane can
// select only an inventoried VM GUID, its recorded display name, and one of the
// compiled-in actions. Both identities must agree locally before mutation.
hyperv_action_result execute_hyperv_virtual_machine_action(
    const std::string& source_id,
    const std::string& expected_name,
    const std::string& action);

}  // namespace ipms::agent::windows
