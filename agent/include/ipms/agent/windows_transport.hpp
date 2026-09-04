#pragma once

#include <string>

namespace ipms::agent::windows {

struct TransportResult {
  bool succeeded{false};
  std::wstring message;
  bool console_active{false};
};

TransportResult run_inventory_cycle();
TransportResult run_telemetry_cycle();
TransportResult run_console_cycle();
TransportResult report_lifecycle_result(
    const std::string& job_id,
    const std::string& result,
    const std::string& result_code);

}  // namespace ipms::agent::windows
