#pragma once

#include <string>

namespace ipms::agent::windows {

// Returns an intentionally bounded, read-only JSON inventory document.
// The caller owns transport; this pack never opens a network connection.
std::string collect_windows_server_core_inventory_json();

// Identity only, using the exact inventory OS-name normalization. The caller
// must isolate potentially blocking WMI reads when a hard deadline is needed.
std::string collect_windows_os_identity_json();

}  // namespace ipms::agent::windows
