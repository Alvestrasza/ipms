#pragma once

#include <string>

namespace ipms::agent::windows {

// Returns an intentionally bounded, read-only JSON inventory document.
// The caller owns transport; this pack never opens a network connection.
std::string collect_windows_server_core_inventory_json();

}  // namespace ipms::agent::windows
