// File Name: gpo_management.hpp
// Version: v0.2.0 | Created: 2026-09-14 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Exact, bounded native pilot-GPO contract and durable execution state.
#pragma once

#include "ipms/agent/management_json.hpp"
#include "ipms/agent/security_gpo_content.hpp"

#include <chrono>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ipms::agent::gpo {
namespace json = management_json;
inline constexpr std::size_t maximum_artifact_bytes = 1024 * 1024;
inline constexpr std::size_t maximum_file_bytes = 512 * 1024;
inline constexpr std::size_t maximum_files = 16;

struct job {
  json::object fields;
  const std::string& text(const char* key) const { return fields.at(key).as<std::string>(); }
  std::int64_t number(const char* key) const { return fields.at(key).as<std::int64_t>(); }
  bool operator==(const job&) const = default;
};

std::string sha256(std::span<const std::uint8_t> bytes);
std::string sha256(std::string_view bytes);
bool valid_uuid(std::string_view value);
bool protected_gpo(std::string_view value);
std::string input_digest(json::object document);
job parse_job(const json::value& document);
bool unexpired(const job& value, std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
json::object local_approval_document(const job& value, std::string_view device_uri);
// Structural validation remains valid for historical receipts. Wall-clock
// validity is checked separately immediately before a grant or execution.
json::object parse_portal_approval(const json::value& document, const job& assignment, std::string_view device_uri);
bool portal_approval_current(const json::value& document, const job& assignment, std::string_view device_uri,
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
const component_descriptor* component(const job& value);
std::vector<std::span<const std::uint8_t>> decode_artifact(
    const component_descriptor& descriptor, std::span<const std::uint8_t> bytes);

// There is deliberately no transition back to prepared after an execution grant
// or a write. A lost create receipt cannot prove that no GPO was created.
enum class phase { prepared, granted, creating, created, importing, terminal, reconciliation };
std::string_view name(phase value);
struct journal {
  job assignment;
  std::string device_uri;
  phase state{phase::prepared};
  std::string gpo_guid;
  std::uint64_t grant_deadline_tick{};
  json::value result;
  json::value portal_approval;
};
json::object journal_document(const journal& value);
journal parse_journal(const json::value& document);
json::object portal_approval_receipt(const journal& record);
bool grant_current(const journal& record, std::uint64_t now_tick);
json::object result(std::string_view status, std::string_view code,
                    std::string_view gpo_guid = {}, json::value evidence = {});
bool valid_result(const json::value& document);
bool executor_matches(const job& assignment, const json::object& executor);

// This seam lets tests prove write ordering and failure fences without AD.
class pilot_provider {
 public:
  virtual ~pilot_provider() = default;
  virtual void preflight() = 0;
  virtual std::string create() = 0;
  virtual void disable(std::string_view guid) = 0;
  virtual void identify(std::string_view guid) = 0;
  virtual void import_settings(std::string_view guid) = 0;
  virtual json::object verify(std::string_view guid) = 0;
};
struct operation_error : std::runtime_error {
  explicit operation_error(std::string code) : std::runtime_error(std::move(code)) {}
};
using persist = std::function<void(const journal&)>;
// A confirmed never-claimed cancellation is different from an uncertain claim.
// This transition is permitted only immediately after this process requested
// its first claim, while the durable granted intent still has a zero deadline.
bool record_claim(journal& record, const json::value& reply,
    std::uint64_t grant_deadline_tick, const persist& save, const json::value& expected_approval = {},
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
json::object execute_pilot(journal& record, pilot_provider& provider,
    const persist& save, const std::function<bool()>& authority,
    const std::function<void()>& consume_approval);
}  // namespace ipms::agent::gpo
