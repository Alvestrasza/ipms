#include "ipms/agent/hyperv_management_guards.hpp"

#include <iostream>

namespace json = ipms::agent::management_json;
namespace journal = ipms::agent::hyperv_management_journal;
using ipms::agent::windows::hyperv_management_command;
using ipms::agent::hyperv::validate_management_command;

int main() {
  constexpr auto vm = "12345678-1234-1234-1234-123456789abc";
  constexpr auto parent = "22345678-1234-1234-1234-123456789abc";
  constexpr auto child = "32345678-1234-1234-1234-123456789abc";
  const std::string revision(64, 'a');
  json::value snapshot = json::object{
      {"vm_source_id", vm}, {"vm_name", "Disposable VM"}, {"revision", revision}, {"state", "stopped"},
      {"collection_status", json::object{{"settings", "collected"}, {"checkpoints", "collected"}}},
      {"capabilities", json::object{{"checkpoint_create", true}, {"checkpoint_delete", true}, {"checkpoint_apply", true}, {"settings_update", false}}},
      {"settings", json::object{{"checkpoint_policy", 5}}},
      {"checkpoints", json::array{
          json::object{{"id", parent}, {"parent_id", nullptr}, {"name", "Before"}, {"can_delete", true}, {"can_apply", true}},
          json::object{{"id", child}, {"parent_id", parent}, {"name", "After"}, {"can_delete", true}, {"can_apply", true}}}}};
  hyperv_management_command create{{vm, "Disposable VM"}, journal::operation::checkpoint_create, revision,
      json::object{{"policy", "configured"}}};
  if (!validate_management_command(create, snapshot).empty()) return 1;
  for (int policy : {2, 3, 4}) {
    snapshot.as<json::object>().at("settings").as<json::object>().at("checkpoint_policy") = policy;
    if (validate_management_command(create, snapshot) != "checkpoint_policy_unsupported") return 2;
  }
  snapshot.as<json::object>().at("settings").as<json::object>().at("checkpoint_policy") = 5;
  create.expected_revision = std::string(64, 'b');
  if (validate_management_command(create, snapshot) != "management_revision_changed") return 3;
  create.expected_revision = revision;
  create.parameters.as<json::object>().emplace("command", "ignored inputs are forbidden");
  if (validate_management_command(create, snapshot) != "invalid_management_command") return 4;
  create.parameters = json::object{{"policy", "configured"}};
  create.target.expected_name = "Another VM";
  if (validate_management_command(create, snapshot) != "vm_identity_conflict") return 5;
  create.target.expected_name = "Disposable VM";
  snapshot.as<json::object>().at("capabilities").as<json::object>().at("checkpoint_create") = false;
  if (validate_management_command(create, snapshot) != "management_operation_unsupported") return 6;
  hyperv_management_command remove{{vm, "Disposable VM"}, journal::operation::checkpoint_delete, revision,
      json::object{{"checkpoint_id", parent}, {"acknowledged_checkpoint_ids", json::array{parent}}}};
  if (validate_management_command(remove, snapshot) != "management_checkpoint_tree_changed") return 7;
  remove.parameters.as<json::object>().at("acknowledged_checkpoint_ids") = json::array{child, parent};
  if (!validate_management_command(remove, snapshot).empty()) return 8;
  remove.parameters.as<json::object>().at("acknowledged_checkpoint_ids") = json::array{parent, parent, child};
  if (validate_management_command(remove, snapshot) != "invalid_management_command") return 9;
  hyperv_management_command apply{{vm, "Disposable VM"}, journal::operation::checkpoint_apply, revision,
      json::object{{"checkpoint_id", parent}, {"confirmation_vm_name", "Disposable VM"}, {"confirmation_checkpoint_name", "Before"}}};
  if (!validate_management_command(apply, snapshot).empty()) return 10;
  snapshot.as<json::object>().at("state") = "running";
  if (validate_management_command(apply, snapshot) != "invalid_vm_state") return 11;
  snapshot.as<json::object>().at("state") = "stopped";
  apply.parameters.as<json::object>().at("confirmation_checkpoint_name") = "After";
  if (validate_management_command(apply, snapshot) != "management_confirmation_mismatch") return 12;
  apply.parameters.as<json::object>().at("confirmation_checkpoint_name") = "Before";
  auto& checkpoints = snapshot.as<json::object>().at("checkpoints").as<json::array>();
  checkpoints[0].as<json::object>().at("parent_id") = child;
  if (validate_management_command(apply, snapshot) != "management_snapshot_unavailable") return 13;
  checkpoints[0].as<json::object>().at("parent_id") = nullptr;
  snapshot.as<json::object>().at("collection_status").as<json::object>().at("checkpoints") = "unavailable";
  if (validate_management_command(apply, snapshot) != "management_snapshot_unavailable") return 14;
  hyperv_management_command configure{{vm, "Disposable VM"}, journal::operation::settings_update, revision,
      json::object{{"section", "processor"}, {"values", json::object{{"count", 4}}}}};
  snapshot.as<json::object>().at("capabilities").as<json::object>().at("settings_update") = true;
  if (!validate_management_command(configure, snapshot).empty()) return 15;
  std::cout << "Hyper-V provider command guards passed: policy, revision, ownership, affected tree, confirmation, state.\n";
  return 0;
}
