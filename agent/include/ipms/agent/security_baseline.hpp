// File Name: security_baseline.hpp
// Version: v0.1.0
// Created: 2026-09-14
// Last Modified: 2026-09-14
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Compiled read-only baseline descriptors and bounded scan contracts.
#pragma once

#include "ipms/agent/management_json.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ipms::agent::security {
namespace json = management_json;
inline constexpr std::size_t max_controls = 2048;
inline constexpr std::size_t controls_per_page = 32;
inline constexpr std::size_t max_pages = 64;
inline constexpr std::size_t max_page_bytes = 48 * 1024;
inline constexpr std::size_t max_output_bytes = 2 * 1024 * 1024;
inline constexpr json::limits page_limits{max_page_bytes, 6, 4096, 2048};

enum class probe_kind { unsupported, registry_value, audit_policy, user_right, account_policy, service_start };

struct control_descriptor {
  std::string_view id;
  probe_kind probe;
  std::string_view scope;
  std::string_view path;
  std::string_view name;
  std::string_view value_type;
};

struct baseline_descriptor {
  std::string_view baseline_id;
  std::string_view profile;
  std::string_view manifest_sha256;
  std::string_view os_build;
  std::span<const control_descriptor> controls;
};

struct scan_job {
  std::string job_id;
  std::string attempt_id;
  std::string baseline_id;
  std::string profile;
  std::string manifest_sha256;
  std::size_t total_controls{};
  std::string expires_at;
  bool operator==(const scan_job&) const = default;
};

std::string_view compiled_catalog_sha256();
const baseline_descriptor* find_baseline(std::string_view baseline_id, std::string_view profile);
bool valid_descriptor(const baseline_descriptor& baseline);
scan_job parse_job(const json::value& document);
json::object job_document(const scan_job& job);
bool matches_manifest(const scan_job& job, const baseline_descriptor& baseline);
bool job_unexpired(const scan_job& job, std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

// Only bounded scalar/string-list observations are transmitted. Unsupported
// or unreadable controls carry null and never become fabricated measurements.
json::object observation(std::string_view id, std::string_view status, json::value value = nullptr);
bool valid_system(const json::object& system);
bool scope_matches(const baseline_descriptor& baseline, const json::object& system);
std::vector<json::object> make_pages(const scan_job& job, const baseline_descriptor& baseline,
                                   const json::object& system, const json::array& controls);
void validate_pages(const scan_job& job, const baseline_descriptor& baseline,
                    const std::vector<json::object>& pages);
}  // namespace ipms::agent::security
