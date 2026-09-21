// File Name: hgs_management.hpp
// Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Fixed HGS operation schema and durable, non-replaying provider state machine.
#pragma once
#include "ipms/agent/management_json.hpp"
#include <chrono>
#include <functional>
#include <optional>
#include <string>

namespace ipms::agent::hgs {
namespace json = management_json;
struct error : std::runtime_error { using std::runtime_error::runtime_error; };
struct job {
  json::object fields;
  const std::string& text(const char* key) const { return fields.at(key).as<std::string>(); }
  const json::object& config() const { return fields.at("config").as<json::object>(); }
  bool operator==(const job&) const = default;
};
job parse_job(const json::value& input);
bool unexpired(const job& assignment, std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
bool bound_to(const job& assignment, std::string_view uri);
void validate_observation(const json::object& observation);
json::object result(std::string_view status, std::string_view code, json::object observation = {});
void validate_result(const json::object& result);
bool postcondition(const job& assignment, const json::object& before, const json::object& after);
bool prerequisites(const job& assignment, const json::object& observation);
enum class phase { prepared, claiming, intent, reboot_wait, terminal };
struct journal {
  job assignment;
  phase state{phase::prepared};
  json::object before;
  json::object outcome;
};
json::object journal_document(const journal& record);
journal parse_journal(const json::value& document);
bool release_matches(const journal& fenced, const json::object& release);
bool permitted_while_fenced(const journal& fenced, const job& offered);
using persist = std::function<void(const journal&)>;
class provider {
 public:
  virtual ~provider() = default;
  virtual json::object inspect(const job& assignment) = 0;
  virtual void apply(const job& assignment) = 0;
};
// The claim callback must return the exact immutable assignment over authenticated
// transport. Persist claiming BEFORE claim and write intent only after the exact
// reply. A lost claim can settle as not invoked; a write intent never replays.
json::object execute(journal& record, provider& local, const persist& save,
    const std::function<bool()>& claim, const std::function<bool()>& authority);
json::object recover(journal& record, provider& local, const persist& save);
}  // namespace ipms::agent::hgs
