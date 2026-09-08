#pragma once

#include "ipms/agent/hyperv_management.hpp"
#include "ipms/agent/hyperv_management_selection.hpp"
#include "ipms/agent/hyperv_management_settings.hpp"

#include <set>

namespace ipms::agent::hyperv {

// Pure preflight shared by native execution and adversarial contract tests.
// This supplements, never replaces, the server's tenant/actor authorization.
inline std::string validate_management_command(
    const windows::hyperv_management_command& command,
    const management_json::value& snapshot) {
  namespace json = management_json;
  using operation = hyperv_management_journal::operation;
  try {
    if (!canonical_guid(command.target.vm_source_id) || command.expected_revision.size() != 64) return "invalid_management_command";
    for (const auto character : command.expected_revision) {
      if (!((character >= 'a' && character <= 'f') || (character >= '0' && character <= '9'))) return "invalid_management_command";
    }
    const auto& document = snapshot.as<json::object>();
    const auto& parameters = command.parameters.as<json::object>();
    if (document.at("vm_source_id").as<std::string>() != command.target.vm_source_id ||
        document.at("vm_name").as<std::string>() != command.target.expected_name) return "vm_identity_conflict";
    if (document.at("revision").as<std::string>() != command.expected_revision) return "management_revision_changed";
    const auto& collection = document.at("collection_status").as<json::object>();
    if (collection.at("settings").as<std::string>() != "collected" ||
        (command.operation != operation::settings_update &&
         collection.at("checkpoints").as<std::string>() != "collected")) return "management_snapshot_unavailable";
    const auto name = std::string(hyperv_management_journal::name(command.operation));
    if (!document.at("capabilities").as<json::object>().at(name).as<bool>()) return "management_operation_unsupported";
    const auto& state = document.at("state").as<std::string>();
    if (command.operation == operation::settings_update) {
      return validate_settings_change(command.parameters, snapshot);
    }
    if (command.operation == operation::checkpoint_create) {
      if (parameters.size() != 1 || parameters.at("policy").as<std::string>() != "configured") return "invalid_management_command";
      if (document.at("settings").as<json::object>().at("checkpoint_policy").as<std::int64_t>() != 5) return "checkpoint_policy_unsupported";
      return state == "running" || state == "stopped" ? "" : "invalid_vm_state";
    }
    if (command.operation != operation::checkpoint_delete && command.operation != operation::checkpoint_apply) return "management_operation_unsupported";
    const auto& selected_id = parameters.at("checkpoint_id").as<std::string>();
    if (!canonical_guid(selected_id)) return "invalid_management_command";
    const json::object* selected = nullptr;
    std::map<std::string, std::string> parents;
    for (const auto& checkpoint : document.at("checkpoints").as<json::array>()) {
      const auto& row = checkpoint.as<json::object>();
      const auto& id = row.at("id").as<std::string>();
      const auto* parent = row.at("parent_id").get_if<std::string>();
      if (!parents.emplace(id, parent ? *parent : "").second) return "management_snapshot_unavailable";
      if (id == selected_id) selected = &row;
    }
    if (!selected) return "management_checkpoint_not_found";
    for (const auto& [id, _] : parents) {
      std::set<std::string> visited;
      auto cursor = id;
      while (!cursor.empty()) {
        const auto found = parents.find(cursor);
        if (found == parents.end() || !visited.insert(cursor).second) return "management_snapshot_unavailable";
        cursor = found->second;
      }
    }
    if (command.operation == operation::checkpoint_apply) {
      if (parameters.size() != 3 || parameters.at("confirmation_vm_name").as<std::string>() != command.target.expected_name ||
          parameters.at("confirmation_checkpoint_name").as<std::string>() != selected->at("name").as<std::string>()) return "management_confirmation_mismatch";
      if (!selected->at("can_apply").as<bool>()) return "management_operation_unsupported";
      return state == "stopped" ? "" : "invalid_vm_state";
    }
    if (parameters.size() != 2 || !selected->at("can_delete").as<bool>()) return "management_operation_unsupported";
    const auto& acknowledged = parameters.at("acknowledged_checkpoint_ids").as<json::array>();
    if (acknowledged.empty() || acknowledged.size() > 256) return "invalid_management_command";
    std::set<std::string> expected;
    for (const auto& value : acknowledged) {
      const auto& id = value.as<std::string>();
      if (!canonical_guid(id) || !expected.insert(id).second) return "invalid_management_command";
    }
    std::set<std::string> affected{selected_id};
    for (;;) {
      const auto count = affected.size();
      for (const auto& [id, parent] : parents) if (affected.contains(parent)) affected.insert(id);
      if (affected.size() == count) break;
    }
    if (expected != affected) return "management_checkpoint_tree_changed";
    return state == "running" || state == "stopped" ? "" : "invalid_vm_state";
  } catch (const std::exception&) { return "invalid_management_command"; }
}

}  // namespace ipms::agent::hyperv
