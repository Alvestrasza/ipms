#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace ipms::agent::hyperv {

inline bool canonical_guid(std::string_view value) {
  if (value.size() != 36) return false;
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (value[index] != '-') return false;
    } else if (!((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) return false;
  }
  return true;
}

struct settings_identity {
  std::string virtual_machine_id;
  std::string type;
};

// A checkpoint can contain the same VM identifier as current settings. Type
// and cardinality are therefore both required; neither row order nor a GUID
// substring in a resource InstanceID can identify the current configuration.
inline std::optional<std::size_t> unique_current_settings(
    std::span<const settings_identity> candidates, std::string_view target) {
  if (!canonical_guid(target)) return std::nullopt;
  std::optional<std::size_t> selected;
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    if (candidates[index].virtual_machine_id != target ||
        candidates[index].type != "Microsoft:Hyper-V:System:Realized") continue;
    if (selected) return std::nullopt;
    selected = index;
  }
  return selected;
}

enum class resource_kind { processor, memory };

// Input is the provider's locally resolved relative settings path, never an
// operator argument. A query stays bound to that exact configuration object.
inline std::wstring current_resource_query(
    std::wstring_view settings_path, resource_kind kind) {
  constexpr std::wstring_view prefix = L"Msvm_VirtualSystemSettingData.InstanceID=";
  if (!settings_path.starts_with(prefix) || settings_path.size() > 512) return {};
  for (wchar_t character : settings_path) {
    if (character < 0x20 || character == 0x7f || character == L'{' || character == L'}') return {};
  }
  const auto suffix = kind == resource_kind::processor
      ? L"Msvm_ProcessorSettingData" : L"Msvm_MemorySettingData";
  return L"ASSOCIATORS OF {" + std::wstring(settings_path) +
      L"} WHERE AssocClass=Msvm_VirtualSystemSettingDataComponent ResultClass=" +
      suffix + L" Role=GroupComponent ResultRole=PartComponent";
}

}  // namespace ipms::agent::hyperv
