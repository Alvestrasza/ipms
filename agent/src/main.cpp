#include "ipms/agent/management_pack.hpp"

#include <iostream>
#include <string_view>

#ifdef _WIN32
#include "ipms/agent/windows_core_pack.hpp"
namespace ipms::agent::windows { int run_windows_service(); }
#else
namespace ipms::agent::linux { int run_linux_service(); }
#endif

int main(int argc, char** argv) {
  const bool console = argc == 2 && std::string_view(argv[1]) == "--console";
  for (const auto& pack : ipms::agent::builtin_management_packs()) if (!ipms::agent::is_valid_pack_assignment(pack)) return 2;
#ifdef _WIN32
  if (console) { std::cout << ipms::agent::windows::collect_windows_server_core_inventory_json() << '\n'; return 0; }
  return ipms::agent::windows::run_windows_service();
#else
  (void)console;
  return ipms::agent::linux::run_linux_service();
#endif
}
