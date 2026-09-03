#include "ipms/agent/management_pack.hpp"

#include <iostream>
#include <string>
#include <string_view>

#ifdef _WIN32
#include "ipms/agent/windows_core_pack.hpp"
#include "ipms/agent/windows_telemetry.hpp"
#include "ipms/agent/windows_transport.hpp"
#include "ipms/agent/windows_updater.hpp"
namespace ipms::agent::windows { int run_windows_service(); }
#else
namespace ipms::agent::linux { int run_linux_service(); }
#endif

int main(int argc, char** argv) {
  const bool console = argc == 2 && std::string_view(argv[1]) == "--console";
  const bool telemetry_console = argc == 2 && std::string_view(argv[1]) == "--telemetry-console";
  const bool run_once = argc == 2 && std::string_view(argv[1]) == "--run-once";
  for (const auto& pack : ipms::agent::builtin_management_packs()) if (!ipms::agent::is_valid_pack_assignment(pack)) return 2;
#ifdef _WIN32
  if (argc >= 2 && std::string_view(argv[1]) == "--apply-lifecycle-update") {
    return ipms::agent::windows::run_windows_updater();
  }
  if (argc == 5 && std::string_view(argv[1]) == "--report-lifecycle-result") {
    const auto result = ipms::agent::windows::report_lifecycle_result(argv[2], argv[3], argv[4]);
    return result.succeeded ? 0 : 4;
  }
  if (console) { std::cout << ipms::agent::windows::collect_windows_server_core_inventory_json() << '\n'; return 0; }
  if (telemetry_console) { std::cout << ipms::agent::windows::collect_windows_telemetry_json() << '\n'; return 0; }
  if (run_once) {
    const auto inventory = ipms::agent::windows::run_inventory_cycle();
    if (!inventory.succeeded) {
      std::wcout << inventory.message << L'\n';
      return 3;
    }
    const auto telemetry = ipms::agent::windows::run_telemetry_cycle();
    std::wcout << (telemetry.succeeded ? L"Inventory and telemetry delivery succeeded." : telemetry.message) << L'\n';
    return telemetry.succeeded ? 0 : 3;
  }
  return ipms::agent::windows::run_windows_service();
#else
  (void)console;
  (void)telemetry_console;
  return ipms::agent::linux::run_linux_service();
#endif
}
