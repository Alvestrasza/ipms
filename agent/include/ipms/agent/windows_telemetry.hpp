#pragma once

#include <string>

namespace ipms::agent::windows {

// Returns one bounded, read-only utilization snapshot. The Control Plane keeps
// only the current sample until a dedicated time-series store is introduced.
std::string collect_windows_telemetry_json();

}  // namespace ipms::agent::windows
