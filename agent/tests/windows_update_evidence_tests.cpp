// File Name: windows_update_evidence_tests.cpp
// Version: v0.1.0
// Created: 2026-09-13
// Last Modified: 2026-09-13
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Installed-evidence contract and actual child-process failure/timeout boundaries.
#include "ipms/agent/windows_update_evidence.hpp"
#include "ipms/agent/management_json.hpp"

#include <windows.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace json = ipms::agent::management_json;
using namespace ipms::agent::windows;

namespace {
json::object evidence(std::size_t count) {
  json::array updates;
  for (std::size_t index = 0; index < count; ++index) {
    // Distinct revisions let the test prove exact GUID/revision preservation.
    updates.emplace_back(json::object{{"update_id", "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"},
        {"revision", index + 1}});
  }
  return {{"source", "wua-local-cache"}, {"status", "collected"},
      {"observed_at", "2026-09-13T12:00:00Z"}, {"updates", updates}};
}

json::object normalized(const json::object& value) {
  return json::parse(normalize_windows_update_evidence_json(json::serialize(value))).as<json::object>();
}

void require(bool condition, const char* description) {
  if (!condition) throw std::runtime_error(description);
}

void require_unavailable(const json::object& value) {
  const auto result = normalized(value);
  require(result.at("status").as<std::string>() == "unavailable", "invalid evidence was accepted");
  require(result.at("updates").as<json::array>().empty(), "partial positives escaped");
  require(result.at("observed_at").get_if<std::nullptr_t>() != nullptr, "failure acquired a freshness timestamp");
}

int fixture_worker() {
  wchar_t fixture[64]{};
  if (!GetEnvironmentVariableW(L"IPMS_TEST_UPDATE_EVIDENCE_FIXTURE", fixture, 64)) return 1;
  if (std::wstring_view(fixture) == L"timeout") { Sleep(30000); return 1; }
  std::string output;
  if (std::wstring_view(fixture) == L"valid") output = json::serialize(evidence(128));
  else if (std::wstring_view(fixture) == L"oversized") output.assign(20000, 'x');
  else if (std::wstring_view(fixture) == L"nonzero") {
    output = json::serialize(evidence(1));
    std::cout << output;
    return 1;
  } else output = "{\"status\":\"collected\"}";
  std::cout << output;
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  // Only this test executable interprets fixture environment variables. The
  // production worker has no configurable query, fixture, or injected program.
  if (argc == 2 && std::string_view(argv[1]) == "--collect-windows-update-evidence") return fixture_worker();
  try {
    auto empty = normalized(evidence(0));
    require(empty.at("status").as<std::string>() == "collected", "empty positive set rejected");
    auto exact = normalized(evidence(128));
    const auto& items = exact.at("updates").as<json::array>();
    require(items.size() == 128, "exact bound not preserved");
    require(items.front().as<json::object>().at("update_id").as<std::string>() ==
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "GUID not canonicalized");
    require(items.back().as<json::object>().at("revision").as<std::int64_t>() == 128, "exact revision lost");
    require(json::serialize(exact).size() < 12 * 1024, "evidence exceeded page header budget");
    auto duplicate = evidence(1);
    duplicate.at("updates").as<json::array>().push_back(duplicate.at("updates").as<json::array>().front());
    require(normalized(duplicate).at("updates").as<json::array>().size() == 1, "duplicate evidence counted twice");
    const auto overflow = normalized(evidence(129));
    require(overflow.at("status").as<std::string>() == "limit-exceeded" &&
        overflow.at("updates").as<json::array>().empty(), "over-limit evidence was silently truncated");
    auto invalid = evidence(1);
    invalid.at("updates").as<json::array>().front().as<json::object>()["revision"] = 0;
    require_unavailable(invalid);
    invalid = evidence(1);
    invalid.at("updates").as<json::array>().front().as<json::object>()["update_id"] = "invalid";
    require_unavailable(invalid);
    invalid = evidence(1); invalid["observed_at"] = "2026-02-30T12:00:00Z"; require_unavailable(invalid);
    invalid = evidence(1); invalid["source"] = "online"; require_unavailable(invalid);
    invalid = evidence(1); invalid["status"] = "unavailable"; require_unavailable(invalid);
    invalid = evidence(1); invalid["status"] = "succeeded-with-errors"; require_unavailable(invalid);
    invalid = evidence(1); invalid["command"] = "forbidden"; require_unavailable(invalid);
    SetEnvironmentVariableW(L"IPMS_TEST_UPDATE_EVIDENCE_FIXTURE", L"valid");
    const auto delivered = json::parse(collect_windows_update_evidence_json(std::chrono::seconds(3))).as<json::object>();
    require(delivered.at("updates").as<json::array>().size() == 128, "actual bounded pipe delivery failed");
    for (const auto* mode : {L"malformed", L"oversized", L"nonzero", L"timeout"}) {
      SetEnvironmentVariableW(L"IPMS_TEST_UPDATE_EVIDENCE_FIXTURE", mode);
      const auto started = std::chrono::steady_clock::now();
      const auto response = json::parse(collect_windows_update_evidence_json(std::chrono::milliseconds(300))).as<json::object>();
      require(response.at("status").as<std::string>() == "unavailable", "failed worker produced positives");
      require(response.at("updates").as<json::array>().empty(), "failed worker leaked partial results");
      require(std::chrono::steady_clock::now() - started < std::chrono::seconds(3), "software collector stalled beyond deadline");
    }
    SetEnvironmentVariableW(L"IPMS_TEST_UPDATE_EVIDENCE_FIXTURE", nullptr);
    std::cout << "PASS: GUID/revision contract, limits, malformed/partial rejection, actual pipe delivery, process deadline.\n";
    return 0;
  } catch (const std::exception& error) {
    SetEnvironmentVariableW(L"IPMS_TEST_UPDATE_EVIDENCE_FIXTURE", nullptr);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
