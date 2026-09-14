// File Name: security_baseline.cpp
// Version: v0.1.0
// Created: 2026-09-14
// Last Modified: 2026-09-14
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Validate exact compiled scan identity, scope and complete bounded result pages.
#include "ipms/agent/security_baseline.hpp"
#include "ipms/agent/security_baseline_content.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>

namespace ipms::agent::security {
namespace {
[[noreturn]] void invalid() { throw std::invalid_argument("Invalid security scan contract."); }
bool token(std::string_view value, std::size_t maximum = 128) {
  return !value.empty() && value.size() <= maximum && std::all_of(value.begin(), value.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
  });
}
bool uuid(std::string_view value) {
  if (value.size() != 36) return false;
  bool nonzero = false;
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return false; }
    else { if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
      nonzero = nonzero || value[i] != '0'; }
  }
  return nonzero;
}
bool digest(std::string_view value) {
  return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}
bool profile(std::string_view value) { return value == "client" || value == "server" || value == "domain-controller"; }
bool clean(std::string_view value, std::size_t maximum) {
  return value.size() <= maximum && std::none_of(value.begin(), value.end(), [](unsigned char c) { return c < 32 || c == 127; });
}
std::chrono::system_clock::time_point expiry(std::string_view value) {
  if (value.size() < 20 || value.size() > 32 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
      value[13] != ':' || value[16] != ':') invalid();
  auto number = [&](std::size_t start, std::size_t count) {
    unsigned result = 0;
    for (std::size_t i = start; i < start + count; ++i) {
      if (value[i] < '0' || value[i] > '9') invalid();
      result = result * 10 + static_cast<unsigned>(value[i] - '0');
    }
    return result;
  };
  const auto year = number(0, 4), month = number(5, 2), day = number(8, 2);
  const auto hour = number(11, 2), minute = number(14, 2), second = number(17, 2);
  const std::chrono::year_month_day date{std::chrono::year(static_cast<int>(year)), std::chrono::month(month), std::chrono::day(day)};
  if (!date.ok() || year < 1970 || year > 2100 || hour > 23 || minute > 59 || second > 59) invalid();
  std::size_t offset = 19;
  unsigned micros = 0, places = 0;
  if (value[offset] == '.') {
    ++offset;
    while (offset < value.size() && value[offset] >= '0' && value[offset] <= '9') {
      if (++places > 6) invalid();
      micros = micros * 10 + static_cast<unsigned>(value[offset++] - '0');
    }
    if (!places) invalid();
    while (places++ < 6) micros *= 10;
  }
  if (value.substr(offset) != "Z" && value.substr(offset) != "+00:00") invalid();
  return std::chrono::sys_days(date) + std::chrono::hours(hour) + std::chrono::minutes(minute) +
      std::chrono::seconds(second) + std::chrono::microseconds(micros);
}
bool measured_value(const json::value& value) {
  if (const auto* number = value.get_if<std::int64_t>()) return *number >= 0 && *number <= 4294967295LL;
  if (const auto* string = value.get_if<std::string>()) return clean(*string, 1024);
  if (const auto* items = value.get_if<json::array>()) {
    return items->size() <= 32 && std::all_of(items->begin(), items->end(), [](const json::value& item) {
      const auto* string = item.get_if<std::string>();
      return string && clean(*string, 1024);
    });
  }
  return false;
}
}  // namespace

std::string_view compiled_catalog_sha256() { return catalog_sha256; }
const baseline_descriptor* find_baseline(std::string_view baseline_id, std::string_view target_profile) {
  for (const auto& item : baselines) if (item.baseline_id == baseline_id && item.profile == target_profile) return &item;
  return nullptr;
}
bool valid_descriptor(const baseline_descriptor& baseline) {
  if (!token(baseline.baseline_id) || !profile(baseline.profile) || !digest(baseline.manifest_sha256) ||
      baseline.os_build.empty() || baseline.os_build.size() > 8 || !std::all_of(baseline.os_build.begin(), baseline.os_build.end(),
          [](char c) { return c >= '0' && c <= '9'; }) || baseline.controls.empty() || baseline.controls.size() > max_controls) return false;
  std::set<std::string_view> seen;
  for (const auto& control : baseline.controls) {
    if (!token(control.id) || !seen.insert(control.id).second ||
        (control.scope != "machine" && control.scope != "user" && control.scope != "domain") ||
        !clean(control.path, 1024) || !clean(control.name, 512)) return false;
  }
  return true;
}
scan_job parse_job(const json::value& document) {
  const auto& fields = document.as<json::object>();
  if (fields.size() != 7) invalid();
  scan_job job{fields.at("job_id").as<std::string>(), fields.at("attempt_id").as<std::string>(),
      fields.at("baseline_id").as<std::string>(), fields.at("profile").as<std::string>(),
      fields.at("manifest_sha256").as<std::string>(), 0, fields.at("expires_at").as<std::string>()};
  const auto count = fields.at("total_controls").as<std::int64_t>();
  if (!uuid(job.job_id) || !uuid(job.attempt_id) || !token(job.baseline_id) || !profile(job.profile) ||
      !digest(job.manifest_sha256) || count < 1 || count > static_cast<std::int64_t>(max_controls)) invalid();
  job.total_controls = static_cast<std::size_t>(count);
  (void)expiry(job.expires_at);
  return job;
}
json::object job_document(const scan_job& job) {
  return {{"job_id", job.job_id}, {"attempt_id", job.attempt_id}, {"baseline_id", job.baseline_id},
      {"profile", job.profile}, {"manifest_sha256", job.manifest_sha256},
      {"total_controls", job.total_controls}, {"expires_at", job.expires_at}};
}
bool matches_manifest(const scan_job& job, const baseline_descriptor& baseline) {
  return valid_descriptor(baseline) && job.baseline_id == baseline.baseline_id && job.profile == baseline.profile &&
      job.manifest_sha256 == baseline.manifest_sha256 && job.total_controls == baseline.controls.size();
}
bool job_unexpired(const scan_job& job, std::chrono::system_clock::time_point now) {
  try { const auto limit = expiry(job.expires_at); return limit > now && limit <= now + std::chrono::minutes(25); }
  catch (...) { return false; }
}
json::object observation(std::string_view id, std::string_view status, json::value value) {
  if (!token(id)) invalid();
  if (status == "ok") {
    if (!measured_value(value) || json::serialize(value).size() > 1024) invalid();
  } else if ((status != "missing" && status != "unsupported" && status != "access_denied" && status != "error" && status != "limit") ||
             !value.get_if<std::nullptr_t>()) invalid();
  return {{"control_id", id}, {"read_status", status}, {"value", std::move(value)}};
}
bool valid_system(const json::object& system) {
  try {
    if (system.size() != 4) return false;
    const auto& build = system.at("os_build").as<std::string>();
    const auto& name = system.at("operating_system").as<std::string>();
    const auto& join = system.at("join_state").as<std::string>();
    const auto product = system.at("product_type").as<std::int64_t>();
    return !build.empty() && build.size() <= 8 && std::all_of(build.begin(), build.end(), [](char c) { return c >= '0' && c <= '9'; }) &&
        !name.empty() && clean(name, 256) && product >= 1 && product <= 3 &&
        (join == "domain" || join == "workgroup" || join == "unknown");
  } catch (...) { return false; }
}
bool scope_matches(const baseline_descriptor& baseline, const json::object& system) {
  if (!valid_system(system) || system.at("os_build").as<std::string>() != baseline.os_build) return false;
  const auto type = system.at("product_type").as<std::int64_t>();
  return (baseline.profile == "client" && type == 1) || (baseline.profile == "domain-controller" && type == 2) ||
      (baseline.profile == "server" && type == 3);
}
std::vector<json::object> make_pages(const scan_job& job, const baseline_descriptor& baseline,
                                   const json::object& system, const json::array& controls) {
  if (controls.size() != job.total_controls) invalid();
  std::vector<json::object> pages;
  const auto count = (controls.size() + controls_per_page - 1) / controls_per_page;
  for (std::size_t offset = 0; offset < controls.size(); offset += controls_per_page) {
    json::array items(controls.begin() + offset, controls.begin() + std::min(offset + controls_per_page, controls.size()));
    pages.emplace_back(json::object{{"job_id", job.job_id}, {"attempt_id", job.attempt_id},
        {"manifest_sha256", job.manifest_sha256}, {"page_index", pages.size()}, {"page_count", count},
        {"system", system}, {"controls", std::move(items)}});
  }
  validate_pages(job, baseline, pages);
  return pages;
}
void validate_pages(const scan_job& job, const baseline_descriptor& baseline, const std::vector<json::object>& pages) {
  if (!matches_manifest(job, baseline) || pages.empty() || pages.size() > max_pages ||
      pages.size() != (job.total_controls + controls_per_page - 1) / controls_per_page) invalid();
  std::size_t seen = 0, total_bytes = 0;
  for (std::size_t index = 0; index < pages.size(); ++index) {
    const auto& page = pages[index];
    total_bytes += json::serialize(page, page_limits).size() + 1;
    if (total_bytes > max_output_bytes || page.size() != 7 || page.at("job_id").as<std::string>() != job.job_id ||
        page.at("attempt_id").as<std::string>() != job.attempt_id || page.at("manifest_sha256").as<std::string>() != job.manifest_sha256 ||
        page.at("page_index").as<std::int64_t>() != static_cast<std::int64_t>(index) ||
        page.at("page_count").as<std::int64_t>() != static_cast<std::int64_t>(pages.size()) ||
        !scope_matches(baseline, page.at("system").as<json::object>()) || page.at("system") != pages[0].at("system")) invalid();
    const auto& controls = page.at("controls").as<json::array>();
    if (controls.size() != std::min(controls_per_page, job.total_controls - seen)) invalid();
    for (const auto& item : controls) {
      const auto& fields = item.as<json::object>();
      if (fields.size() != 3 || fields.at("control_id").as<std::string>() != baseline.controls[seen++].id) invalid();
      if (observation(fields.at("control_id").as<std::string>(), fields.at("read_status").as<std::string>(), fields.at("value")) != fields) invalid();
    }
  }
  if (seen != job.total_controls) invalid();
}
}  // namespace ipms::agent::security
