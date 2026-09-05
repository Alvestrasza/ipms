#pragma once

#include <string>
#include <cstdint>
#include <functional>
#include <vector>

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

struct hyperv_console_input {
  std::string id;
  std::string type;
  std::uint32_t key_code{};
  bool is_down{false};
  std::int32_t x{};
  std::int32_t y{};
  std::uint32_t button{};
  std::int32_t delta{};
};

struct hyperv_console_result {
  bool succeeded{false};
  std::string result_code;
  std::vector<std::uint8_t> png;
  std::uint16_t width{};
  std::uint16_t height{};
  std::vector<std::string> acknowledged_input_ids;
};

// Captures one bounded local VM console frame and applies only typed keyboard
// and mouse events to that exact VM. No guest network connection or command
// execution is involved.
hyperv_console_result execute_hyperv_console_cycle(
    const std::string& source_id,
    const std::string& expected_name,
    std::uint16_t width,
    std::uint16_t height,
    const std::vector<hyperv_console_input>& inputs);

// Applies one ordered typed batch without capturing/encoding an image. The
// cancellation check is repeated before each VM input method invocation.
hyperv_console_result execute_hyperv_console_inputs(
    const std::string& source_id,
    const std::string& expected_name,
    const std::vector<hyperv_console_input>& inputs,
    const std::function<bool()>& cancelled);

}  // namespace ipms::agent::windows
