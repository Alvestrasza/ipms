// File Name: windows_group_policy_tests.cpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Synthetic all-CSE evidence and actual fixed-process failure boundaries.
#include "ipms/agent/windows_group_policy.hpp"
#include "ipms/agent/management_json.hpp"
#include "ipms/agent/periodic_worker.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace json = ipms::agent::management_json;
using namespace ipms::agent::windows;
namespace {
constexpr auto observed = "2026-09-14T12:00:00Z";
constexpr auto policy = "11111111-1111-4111-8111-111111111111";
constexpr auto first_cse = "22222222-2222-4222-8222-222222222222";
constexpr auto second_cse = "33333333-3333-4333-8333-333333333333";
constexpr auto domain = "44444444-4444-4444-8444-444444444444";
constexpr auto path = "CN={11111111-1111-4111-8111-111111111111},CN=Policies,CN=System,DC=example,DC=invalid";
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
group_policy_snapshot fixture() {
  group_policy_snapshot snapshot;
  snapshot.domain_joined = true; snapshot.domain_dns = "example.invalid"; snapshot.domain_guid = domain;
  snapshot.gpos.push_back({policy, path, 65537, true, false, true, {first_cse, second_cse}});
  snapshot.extensions = {
    {first_cse, "20260914090000.000000+000", "20260914090001.000000+000", 1, 0},
    {second_cse, "20260914100000.000000+000", "20260914100001.000000+000", 1, 0}
  };
  snapshot.history = {{first_cse, {{policy, path, 65537, false}}}, {second_cse, {{policy, path, 65537, false}}}};
  return snapshot;
}
json::object evidence(const group_policy_snapshot& snapshot) {
  return json::parse(evaluate_windows_group_policy(snapshot, snapshot, observed)).as<json::object>();
}
std::string gpo_status(const group_policy_snapshot& snapshot) {
  return evidence(snapshot).at("gpos").as<json::array>().at(0).as<json::object>().at("status").as<std::string>();
}
void no_positive(const std::string& document) {
  const auto root = json::parse(document).as<json::object>();
  require(root.at("status").as<std::string>() != "collected" && root.at("gpos").as<json::array>().empty(),
      "Incomplete evidence retained positive GPOs");
}
void timestamp_tests() {
  require(group_policy_wmi_time_to_utc("20260914010000.123456+120") == "2026-09-13T23:00:00Z", "Positive UTC offset was reversed");
  require(group_policy_wmi_time_to_utc("20260914233000.000001-090") == "2026-09-15T01:00:00Z", "Negative UTC offset was reversed");
  require(group_policy_wmi_time_to_utc("20240229000000.000000+000") == "2024-02-29T00:00:00Z", "Leap day rejected");
  for (const auto* value : {"20250229000000.000000+000", "20260914240000.000000+000",
      "20260914000000.******+000", "20260914000000.000000+***", "20260914000000.000000:000",
      "2026-09-14T00:00:00Z", "", "20260914000000.000000+000x"})
    require(group_policy_wmi_time_to_utc(value).empty(), "Malformed or wildcard timestamp became evidence");
}
void decision_tests() {
  auto snapshot = fixture();
  const auto positive = evidence(snapshot);
  const auto& record = positive.at("gpos").as<json::array>().at(0).as<json::object>();
  require(positive.at("status").as<std::string>() == "collected" && record.at("status").as<std::string>() == "applied",
      "Exact domain GUID/GPO/version and successful all-CSE processing was rejected");
  require(record.at("processed_at").as<std::string>() == "2026-09-14T09:00:01Z",
      "Collection time or newest CSE hid older processing evidence");
  require(record.size() == 4 && positive.size() == 8 && !positive.contains("name"), "Unexpected metadata escaped the wire contract");
  require(normalize_windows_group_policy_json(json::serialize(positive)) == json::serialize(positive), "Valid compact contract failed normalization");
  for (unsigned reason = 0; reason < 3; ++reason) {
    snapshot = fixture();
    if (reason == 0) snapshot.gpos[0].enabled = false;
    if (reason == 1) snapshot.gpos[0].access_denied = true;
    if (reason == 2) snapshot.gpos[0].filter_allowed = false;
    require(gpo_status(snapshot) == "excluded", "Disabled, access-denied or WMI-filter-excluded GPO was counted");
    require(evidence(snapshot).at("gpos").as<json::array>()[0].as<json::object>().at("processed_at").get_if<std::nullptr_t>(),
        "Excluded GPO retained a successful timestamp");
  }
  for (unsigned reason = 0; reason < 7; ++reason) {
    snapshot = fixture();
    if (reason == 0) snapshot.history[1].gpos.clear();
    if (reason == 1) snapshot.history[1].gpos[0].version++;
    if (reason == 2) snapshot.history[1].gpos[0].disabled = true;
    if (reason == 3) snapshot.history[1].gpos[0].directory_path += ",DC=other";
    if (reason == 4) snapshot.gpos[0].directory_path += ",DC=other";
    if (reason == 5) snapshot.gpos[0].extension_ids.clear();
    if (reason == 6) snapshot.extensions.pop_back();
    require(gpo_status(snapshot) == "unknown", "Missing CSE, stale version, foreign domain or empty extension coverage became applied");
  }
  snapshot = fixture(); snapshot.extensions[0].error = 5;
  require(gpo_status(snapshot) == "failed", "Failed CSE processing was counted");
  snapshot = fixture(); snapshot.extensions[0].logging_status = 3;
  require(gpo_status(snapshot) == "unknown", "Unsupported RSoP logging became applied");
  snapshot = fixture(); snapshot.extensions[0].end_time = "20260914120000.999999+000";
  require(gpo_status(snapshot) == "applied", "Valid same-second CSE completion lost the observation's subsecond precision");
  for (const auto* future : {"20260914120001.000000+000", "20260914120100.000000+000"}) {
    snapshot = fixture(); snapshot.extensions[0].end_time = future;
    no_positive(evaluate_windows_group_policy(snapshot, snapshot, observed));
  }
  for (unsigned reason = 0; reason < 8; ++reason) {
    snapshot = fixture();
    if (reason == 0) snapshot.extensions[0].logging_status = 2;
    if (reason == 1) snapshot.extensions[0].end_time = "";
    if (reason == 2) snapshot.extensions[0].begin_time = "20260914090002.000000+000";
    if (reason == 3) { snapshot.extensions[0].begin_time = "20260914090001.999999+000"; }
    if (reason == 4) snapshot.extensions[0].end_time = "20260914120501.000000+000";
    if (reason == 5) snapshot.domain_guid = "00000000-0000-0000-0000-000000000000";
    if (reason == 6) snapshot.gpos.push_back(snapshot.gpos.front());
    if (reason == 7) snapshot.history.push_back(snapshot.history.front());
    no_positive(evaluate_windows_group_policy(snapshot, snapshot, observed));
  }
  snapshot = fixture(); snapshot.extensions.push_back({"00000000-0000-0000-0000-000000000000",
      "20260914090000.000000+000", "20260914090001.000000+000", 1, 5});
  no_positive(evaluate_windows_group_policy(snapshot, snapshot, observed));
  for (unsigned change = 0; change < 4; ++change) {
    snapshot = fixture(); auto after = snapshot;
    if (change == 0) after.domain_guid = first_cse;
    if (change == 1) after.history[0].gpos[0].version++;
    if (change == 2) after.gpos[0].version++;
    if (change == 3) after.extensions[0].end_time = "20260914090001.000001+000";
    no_positive(evaluate_windows_group_policy(snapshot, after, observed));
  }
  snapshot = fixture(); auto reordered = snapshot;
  std::reverse(reordered.gpos[0].extension_ids.begin(), reordered.gpos[0].extension_ids.end());
  std::reverse(reordered.extensions.begin(), reordered.extensions.end());
  std::reverse(reordered.history.begin(), reordered.history.end());
  require(json::parse(evaluate_windows_group_policy(snapshot, reordered, observed)).as<json::object>() == positive,
      "Provider row order was incorrectly treated as changing policy");
  require(evidence({}).at("status").as<std::string>() == "not-domain-joined", "Standalone computer became domain evidence");
  snapshot = fixture(); snapshot.gpos.resize(257, snapshot.gpos.front());
  no_positive(evaluate_windows_group_policy(snapshot, snapshot, observed));
  snapshot = fixture(); snapshot.gpos[0].extension_ids.resize(33, first_cse);
  no_positive(evaluate_windows_group_policy(snapshot, snapshot, observed));
  snapshot = fixture(); snapshot.extensions.resize(65, snapshot.extensions.front());
  no_positive(evaluate_windows_group_policy(snapshot, snapshot, observed));
  for (unsigned corruption = 0; corruption < 8; ++corruption) {
    auto malformed = positive;
    if (corruption == 0) malformed["scope"] = "user";
    if (corruption == 1) malformed["domain_guid"] = nullptr;
    if (corruption == 2) malformed["status"] = "incomplete";
    if (corruption == 3) malformed["gpos"].as<json::array>().push_back(malformed["gpos"].as<json::array>()[0]);
    if (corruption == 4) malformed["gpos"].as<json::array>()[0].as<json::object>()["version"] = -1;
    if (corruption == 5) malformed["gpos"].as<json::array>()[0].as<json::object>()["processed_at"] = nullptr;
    if (corruption == 6) malformed["gpos"].as<json::array>()[0].as<json::object>()["display_name"] = "Pretend Microsoft baseline";
    if (corruption == 7) malformed["gpos"].as<json::array>()[0].as<json::object>()["processed_at"] = "2026-09-14T12:00:01Z";
    no_positive(normalize_windows_group_policy_json(json::serialize(malformed)));
  }
}
void inventory_binding_tests() {
  const auto valid = evaluate_windows_group_policy(fixture(), fixture(), observed);
  require(bind_windows_group_policy_domain(valid, "example.invalid") == valid, "Matching captured core domain rejected");
  require(bind_windows_group_policy_domain(valid, "ExAmPlE.InVaLiD") == valid, "Equivalent core DNS case changed the domain identity");
  for (const auto* domain_name : {"", "different.example.invalid", "example.invalid.", "example.invalid/path", "127.0.0.1"}) {
    const auto bound = json::parse(bind_windows_group_policy_domain(valid, domain_name)).as<json::object>();
    require(bound.at("status").as<std::string>() == "incomplete" && bound.at("gpos").as<json::array>().empty() &&
        bound.at("domain_dns").get_if<std::nullptr_t>() && bound.at("domain_guid").get_if<std::nullptr_t>(),
        "Absent, invalid or mismatching core domain retained positive GPO evidence");
    require(bound.at("observed_at").as<std::string>() == observed, "Domain binding refreshed the original observation clock");
  }
  for (const auto* invalid : {"null", "{}", "{", "[]"})
    require(json::parse(bind_windows_group_policy_domain(invalid, "example.invalid")).as<json::object>()
        .at("status").as<std::string>() == "incomplete", "Malformed evidence was not isolated to the GPO field");
  const auto standalone = evaluate_windows_group_policy({}, {}, observed);
  require(bind_windows_group_policy_domain(standalone, "") == standalone, "A valid standalone observation lost its explicit status");
  auto numeric = fixture(); numeric.domain_dns = "127.0.0.1";
  no_positive(evaluate_windows_group_policy(numeric, numeric, observed));
}
int fixture_worker() {
  wchar_t mode[64]{};
  if (!GetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_FIXTURE", mode, 64)) return 1;
  wchar_t pid_path[32768]{};
  if (GetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_PID_FILE", pid_path, 32768)) {
    std::ofstream file{std::filesystem::path(pid_path)}; file << GetCurrentProcessId();
  }
  if (std::wstring_view(mode) == L"timeout") { Sleep(30000); return 1; }
  if (std::wstring_view(mode) == L"oversized") { std::cout << std::string(70000, 'x'); return 0; }
  if (std::wstring_view(mode) == L"malformed") { std::cout << "{}"; return 0; }
  if (std::wstring_view(mode) == L"empty") return 0;
  auto snapshot = fixture();
  if (std::wstring_view(mode) == L"incomplete") snapshot.extensions[0].logging_status = 2;
  std::cout << evaluate_windows_group_policy(snapshot, snapshot, observed);
  return std::wstring_view(mode) == L"nonzero" ? 1 : 0;
}
}  // namespace

int main(int argc, char** argv) {
  // Fixture selection is compiled into this test binary only. The production
  // executable never reads these variables and exposes no test data injection.
  if (argc == 2 && std::string_view(argv[1]) == "--collect-windows-group-policy") return fixture_worker();
  std::filesystem::path pid_path;
  try {
    timestamp_tests(); decision_tests(); inventory_binding_tests();
    wchar_t temporary[32768]{};
    require(GetTempPathW(32768, temporary) != 0, "Temporary path unavailable");
    pid_path = std::filesystem::path(temporary) / (L"ipms-gpo-evidence-fixture-" + std::to_wstring(GetCurrentProcessId()) + L".pid");
    SetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_PID_FILE", pid_path.c_str());
    SetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_FIXTURE", L"valid");
    const auto result = json::parse(collect_windows_group_policy_json({}, std::chrono::seconds(3))).as<json::object>();
    require(result.at("status").as<std::string>() == "collected" && result.at("gpos").as<json::array>().size() == 1,
        "Complete child output was not drained and delivered");
    for (const auto* mode : {L"malformed", L"oversized", L"nonzero", L"empty", L"incomplete", L"timeout"}) {
      SetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_FIXTURE", mode);
      const auto began = std::chrono::steady_clock::now();
      no_positive(collect_windows_group_policy_json({}, std::chrono::milliseconds(400)));
      require(std::chrono::steady_clock::now() - began < std::chrono::seconds(3), "Native worker exceeded its process deadline");
      DWORD child_pid{};
      { std::ifstream file(pid_path); file >> child_pid; }
      if (child_pid) {
        const auto process = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
        if (process) {
          const auto exited = WaitForSingleObject(process, 2000); CloseHandle(process);
          require(exited == WAIT_OBJECT_0, "Disposable child survived rejection");
        }
      }
    }
    SetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_FIXTURE", L"timeout");
    std::atomic<unsigned> heartbeats{};
    ipms::agent::periodic_worker heartbeat(std::chrono::milliseconds(10), [&](const auto&) { ++heartbeats; });
    const auto began = std::chrono::steady_clock::now();
    no_positive(collect_windows_group_policy_json([&] { return std::chrono::steady_clock::now() - began > std::chrono::milliseconds(200); }));
    heartbeat.stop();
    require(heartbeats.load() >= 3 && std::chrono::steady_clock::now() - began < std::chrono::seconds(3),
        "Hung native observation ignored cancellation or stalled independent heartbeat");
    SetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_FIXTURE", nullptr);
    SetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_PID_FILE", nullptr);
    std::filesystem::remove(pid_path);
    std::cout << "PASS: exact domain/GPO identity, all-CSE history/version/success, exclusion, dirty/unstable evidence, timestamps, bounds, child cleanup and cancellation.\n";
    return 0;
  } catch (const std::exception& error) {
    SetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_FIXTURE", nullptr);
    SetEnvironmentVariableW(L"IPMS_TEST_GROUP_POLICY_PID_FILE", nullptr);
    if (!pid_path.empty()) { std::error_code ignored; std::filesystem::remove(pid_path, ignored); }
    std::cerr << error.what() << '\n'; return 1;
  }
}
