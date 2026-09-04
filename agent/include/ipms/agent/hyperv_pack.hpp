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

}  // namespace ipms::agent::windows
