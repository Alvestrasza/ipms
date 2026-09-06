#include "ipms/agent/hyperv_management_settings.hpp"

#include <iostream>

namespace json = ipms::agent::management_json;
namespace journal = ipms::agent::hyperv_management_journal;
using namespace ipms::agent::hyperv;
using ipms::agent::windows::hyperv_management_command;

int main() {
  if (!valid_settings_name(std::string(100, 'a')) || valid_settings_name(std::string(101, 'a'))) return 1;
  if (valid_settings_name("bad\nname") || valid_settings_name(std::string("bad\0name", 8))) return 2;
  std::string emoji;
  for (unsigned index = 0; index < 50; ++index) emoji += "\xF0\x9F\x98\x80";
  if (!valid_settings_name(emoji) || valid_settings_name(emoji + "a")) return 3;
  std::string three_byte;
  for (unsigned index = 0; index < 86; ++index) three_byte += "\xE2\x82\xAC";
  if (valid_settings_name(three_byte)) return 4;
  if (valid_settings_name("\xED\xA0\x80") || valid_settings_name("\xC0\x80")) return 5;
  json::value parameters = json::object{{"section", "general"},
      {"values", json::object{{"name", "New VM name"}, {"notes", "A note\r\nSecond line"}}}};
  if (!validate_settings_parameters(parameters).empty()) return 6;
  parameters.as<json::object>().at("values").as<json::object>().emplace("InstanceID", "forbidden");
  if (validate_settings_parameters(parameters).empty()) return 7;
  parameters.as<json::object>().at("values").as<json::object>().erase("InstanceID");
  constexpr auto vm_id = "12345678-1234-1234-1234-123456789abc";
  hyperv_management_command command{{vm_id, "Old VM name"}, journal::operation::settings_update,
      std::string(64, 'a'), parameters};
  const auto target = settings_result_target(command);
  if (target.vm_source_id != vm_id || target.expected_name != "New VM name" || command.target.expected_name != "Old VM name") return 8;
  json::value snapshot = json::object{{"vm_source_id", vm_id}, {"vm_name", "New VM name"}, {"state", "stopped"},
      {"collection_status", json::object{{"settings", "collected"}, {"checkpoints", "unavailable"}}},
      {"settings", json::object{{"name", "New VM name"}, {"notes", "A note\r\nSecond line"},
          {"processor", json::object{{"count", 4}}},
          {"memory", json::object{{"startup_mib", 2048}, {"minimum_mib", 1024}, {"maximum_mib", 4096}, {"dynamic_enabled", true}}}}}};
  if (!settings_postcondition(command, snapshot)) return 9;
  snapshot.as<json::object>().at("settings").as<json::object>().at("notes") = "A note\nSecond line";
  if (settings_postcondition(command, snapshot)) return 10;
  command.parameters = json::object{{"section", "processor"}, {"values", json::object{{"count", 4}}}};
  snapshot.as<json::object>().at("vm_name") = "Old VM name";
  if (!validate_settings_parameters(command.parameters).empty() || !settings_postcondition(command, snapshot)) return 11;
  command.parameters.as<json::object>().at("values").as<json::object>().at("count") = true;
  if (validate_settings_parameters(command.parameters).empty()) return 12;
  command.parameters.as<json::object>().at("values").as<json::object>().at("count") = 2049;
  if (validate_settings_parameters(command.parameters).empty()) return 13;
  command.parameters = json::object{{"section", "memory"}, {"values", json::object{
      {"startup_mib", 2048}, {"minimum_mib", 1024}, {"maximum_mib", 4096}, {"dynamic_enabled", true}}}};
  if (!validate_settings_parameters(command.parameters).empty() || !settings_postcondition(command, snapshot)) return 14;
  command.parameters.as<json::object>().at("values").as<json::object>().at("minimum_mib") = 4096;
  if (validate_settings_parameters(command.parameters).empty()) return 15;
  command.parameters.as<json::object>().at("values").as<json::object>().at("minimum_mib") = 1024;
  snapshot.as<json::object>().at("state") = "running";
  if (settings_postcondition(command, snapshot)) return 16;
  snapshot.as<json::object>().at("state") = "stopped";
  snapshot.as<json::object>().at("collection_status").as<json::object>().at("settings") = "unavailable";
  if (settings_postcondition(command, snapshot)) return 17;
  command.parameters = json::object{{"section", "network"}, {"values", json::object{}}};
  if (validate_settings_parameters(command.parameters).empty()) return 18;
  std::cout << "Hyper-V typed settings guards passed: Unicode, bounds, allowlists, identity and exact postconditions.\n";
  return 0;
}
