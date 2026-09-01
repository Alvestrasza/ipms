#pragma once

#include <string>

namespace ipms::agent::windows {

struct TransportResult {
  bool succeeded{false};
  std::wstring message;
};

TransportResult run_inventory_cycle();
TransportResult run_telemetry_cycle();

}  // namespace ipms::agent::windows
