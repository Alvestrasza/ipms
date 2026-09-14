// File Name: windows_security_scan.hpp
// Version: v0.1.0
// Created: 2026-09-14
// Last Modified: 2026-09-14
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Fixed native read-only scan worker with process and evidence limits.
#pragma once

#include "ipms/agent/security_baseline.hpp"

#include <chrono>
#include <functional>

namespace ipms::agent::windows {
struct security_scan_result {
  std::vector<security::json::object> pages;
  std::string error_code;
};

// Only the fixed child mode of this executable is launched. The job may
// select a compiled manifest, never a command, program, path or native query.
security_scan_result collect_security_baseline(const security::scan_job& job,
    const std::function<bool()>& cancelled = {},
    std::chrono::milliseconds timeout = std::chrono::seconds(30));
int run_security_baseline_worker();

// The same pure decoder is used by the Windows reader and fixture tests.
security::json::object decode_security_registry_value(const security::control_descriptor& control,
    std::uint32_t type, std::span<const std::uint8_t> data);
security::json::object decode_security_account_duration(const security::control_descriptor& control,
    std::uint32_t seconds);
}  // namespace ipms::agent::windows
