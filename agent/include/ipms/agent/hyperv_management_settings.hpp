#pragma once

#include "ipms/agent/hyperv_management.hpp"

namespace ipms::agent::hyperv {

inline bool valid_settings_name(const std::string& name) {
  if (name.empty() || name.size() > 256) return false;
  std::size_t units = 0;
  for (const unsigned char character : name) {
    if (character < 0x20 || character == 0x7f) return false;
    if ((character & 0xc0) == 0x80) continue;
    units += character >= 0xf0 ? 2 : 1;
  }
  if (units > 100) return false;
  // The shared codec validates full Unicode scalar/UTF-8 correctness.
  try { (void)management_json::serialize(name); }
  catch (const std::exception&) { return false; }
  return true;
}

inline std::string validate_settings_parameters(const management_json::value& parameters) {
  namespace json = management_json;
  try {
    const auto& fields = parameters.as<json::object>();
    if (fields.size() != 2) return "invalid_management_command";
    const auto& section = fields.at("section").as<std::string>();
    const auto& values = fields.at("values").as<json::object>();
    if (section == "general") {
      if (values.size() != 2 || !valid_settings_name(values.at("name").as<std::string>())) return "invalid_management_command";
      const auto& notes = values.at("notes").as<std::string>();
      if (notes.size() > 4096) return "invalid_management_command";
      for (const unsigned char character : notes) if ((character < 0x20 && character != '\n' && character != '\r' && character != '\t') || character == 0x7f) return "invalid_management_command";
      (void)json::serialize(notes);
      return {};
    }
    if (section == "processor") {
      if (values.size() != 1) return "invalid_management_command";
      const auto count = values.at("count").as<std::int64_t>();
      return count >= 1 && count <= 2048 ? "" : "invalid_management_command";
    }
    if (section != "memory" || values.size() != 4) return "invalid_management_command";
    const auto startup = values.at("startup_mib").as<std::int64_t>();
    const auto minimum = values.at("minimum_mib").as<std::int64_t>();
    const auto maximum = values.at("maximum_mib").as<std::int64_t>();
    (void)values.at("dynamic_enabled").as<bool>();
    return minimum >= 1 && minimum <= startup && startup <= maximum && maximum <= (1LL << 40)
        ? "" : "invalid_management_command";
  } catch (const std::exception&) { return "invalid_management_command"; }
}

inline windows::hyperv_management_target settings_result_target(const windows::hyperv_management_command& command) {
  auto target = command.target;
  if (command.operation != hyperv_management_journal::operation::settings_update) return target;
  if (!validate_settings_parameters(command.parameters).empty()) return target;
  const auto& fields = command.parameters.as<management_json::object>();
  if (fields.at("section").as<std::string>() == "general") {
    target.expected_name = fields.at("values").as<management_json::object>().at("name").as<std::string>();
  }
  return target;
}

inline bool settings_postcondition(const windows::hyperv_management_command& command,
    const management_json::value& snapshot) {
  namespace json = management_json;
  try {
    if (!validate_settings_parameters(command.parameters).empty()) return false;
    const auto& requested = command.parameters.as<json::object>();
    const auto& section = requested.at("section").as<std::string>();
    const auto& values = requested.at("values").as<json::object>();
    const auto& document = snapshot.as<json::object>();
    if (document.at("vm_source_id").as<std::string>() != command.target.vm_source_id ||
        document.at("vm_name").as<std::string>() != settings_result_target(command).expected_name ||
        document.at("state").as<std::string>() != "stopped" ||
        document.at("collection_status").as<json::object>().at("settings").as<std::string>() != "collected") return false;
    const auto& settings = document.at("settings").as<json::object>();
    const auto& observed = section == "general" ? settings : settings.at(section).as<json::object>();
    if (section == "general" && document.at("vm_name") != values.at("name")) return false;
    for (const auto& [key, value] : values) if (observed.at(key) != value) return false;
    return true;
  } catch (const std::exception&) { return false; }
}

}  // namespace ipms::agent::hyperv
