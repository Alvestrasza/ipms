#pragma once

#include <string>

namespace ipms::agent::windows {

struct TransportResult {
  bool succeeded{false};
  std::wstring message;
};

TransportResult run_inventory_cycle();
TransportResult run_telemetry_cycle();
TransportResult report_lifecycle_result(
    const std::string& job_id,
    const std::string& result,
    const std::string& result_code);

}  // namespace ipms::agent::windows
