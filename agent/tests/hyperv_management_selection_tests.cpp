#include "ipms/agent/hyperv_management_selection.hpp"

#include <algorithm>
#include <array>
#include <iostream>

using namespace ipms::agent::hyperv;

int main() {
  constexpr auto target = "12345678-1234-1234-1234-123456789abc";
  constexpr auto other = "22345678-1234-1234-1234-123456789abc";
  std::array<settings_identity, 4> rows{{
      {target, "Microsoft:Hyper-V:Snapshot:Realized"},
      {target, "Microsoft:Hyper-V:System:Realized"},
      {target, "Microsoft:Hyper-V:Snapshot:Recovery"},
      {other, "Microsoft:Hyper-V:System:Realized"},
  }};
  // Snapshot rows carry different resource values but are never queried. The
  // current configuration remains the source before and after row reordering.
  std::array<unsigned, 4> cpu{{1, 8, 2, 32}};
  std::array<unsigned, 4> memory{{512, 8192, 1024, 65536}};
  const auto selected = unique_current_settings(rows, target);
  if (!selected || cpu[*selected] != 8 || memory[*selected] != 8192) return 1;
  std::reverse(rows.begin(), rows.end());
  std::reverse(cpu.begin(), cpu.end());
  std::reverse(memory.begin(), memory.end());
  const auto reversed = unique_current_settings(rows, target);
  if (!reversed || cpu[*reversed] != 8 || memory[*reversed] != 8192) return 2;
  rows[0] = {target, "Microsoft:Hyper-V:System:Realized"};
  if (unique_current_settings(rows, target)) return 3;
  if (unique_current_settings(rows, "invalid-guid")) return 4;
  std::array<settings_identity, 1> snapshot_only{{
      {target, "Microsoft:Hyper-V:Snapshot:Realized"}}};
  if (unique_current_settings(snapshot_only, target)) return 5;
  const std::wstring current_path =
      L"Msvm_VirtualSystemSettingData.InstanceID=\"Microsoft:12345678-1234-1234-1234-123456789abc\"";
  const auto query = current_resource_query(current_path, resource_kind::processor);
  if (query != L"ASSOCIATORS OF {" + current_path +
      L"} WHERE AssocClass=Msvm_VirtualSystemSettingDataComponent ResultClass=Msvm_ProcessorSettingData Role=GroupComponent ResultRole=PartComponent") return 6;
  if (current_resource_query(current_path, resource_kind::memory).find(
      L"ResultClass=Msvm_MemorySettingData") == std::wstring::npos) return 7;
  if (!current_resource_query(L"Msvm_ComputerSystem.Name=\"x\"", resource_kind::memory).empty()) return 8;
  if (!current_resource_query(current_path + L"} WHERE", resource_kind::memory).empty()) return 9;
  if (!current_resource_query(current_path + L"\n", resource_kind::memory).empty()) return 10;
  if (canonical_guid("12345678-1234-1234-1234-123456789abC")) return 11;
  std::cout << "Hyper-V current-setting and resource-association guards passed.\n";
  return 0;
}
