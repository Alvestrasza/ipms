// File Name: windows_group_policy.hpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Bounded local computer GPO processing evidence, independent of resultant settings.
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace ipms::agent::windows {
struct group_policy_gpo {
  std::string guid, directory_path;
  std::uint32_t version{};
  bool enabled{}, access_denied{}, filter_allowed{};
  std::vector<std::string> extension_ids;
  bool operator==(const group_policy_gpo&) const = default;
};
struct group_policy_extension {
  std::string guid;
  // Exact WMI DMTF timestamps are retained for before/after consistency.
  std::string begin_time, end_time;
  std::uint32_t logging_status{}, error{};
  bool operator==(const group_policy_extension&) const = default;
};
struct group_policy_history_gpo {
  std::string guid, directory_path;
  std::uint32_t version{};
  bool disabled{};
  bool operator==(const group_policy_history_gpo&) const = default;
};
struct group_policy_history {
  std::string extension_guid;
  std::vector<group_policy_history_gpo> gpos;
  bool operator==(const group_policy_history&) const = default;
};
struct group_policy_snapshot {
  bool domain_joined{};
  std::string domain_dns, domain_guid;
  std::vector<group_policy_gpo> gpos;
  std::vector<group_policy_extension> extensions;
  std::vector<group_policy_history> history;
  bool operator==(const group_policy_snapshot&) const = default;
};

// Fixed local API reads only. No parameters select a query, remote computer,
// policy, executable or path. All COM/RPC work stays inside a disposable child.
std::string collect_windows_group_policy_json(const std::function<bool()>& cancelled = {},
    std::chrono::milliseconds timeout = std::chrono::seconds(30));
int run_windows_group_policy_worker();

// Stable native observation seams also used by synthetic fixture tests.
std::string group_policy_wmi_time_to_utc(std::string_view timestamp);
std::string evaluate_windows_group_policy(group_policy_snapshot before,
    group_policy_snapshot after, std::string_view observed_at);
std::string normalize_windows_group_policy_json(std::string_view document);
// Bind only to the domain already captured by core inventory. A mismatch must
// invalidate GPO evidence without invalidating the rest of the host inventory.
std::string bind_windows_group_policy_domain(std::string_view document, std::string_view expected_domain);
}  // namespace ipms::agent::windows
