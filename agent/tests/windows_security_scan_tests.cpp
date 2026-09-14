// File Name: windows_security_scan_tests.cpp
// Version: v0.1.0
// Created: 2026-09-14
// Last Modified: 2026-09-14
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Synthetic native decoder and actual disposable-process failure boundaries.
#include "ipms/agent/windows_security_scan.hpp"
#include "ipms/agent/windows_core_pack.hpp"
#include "ipms/agent/periodic_worker.hpp"

#include <windows.h>

#include <atomic>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace security = ipms::agent::security;
namespace json = ipms::agent::management_json;
using namespace ipms::agent::windows;

// Link-time test collaborator: no real WMI/native identity scan is needed by
// these subprocess fixtures. Production links the existing inventory reader.
namespace ipms::agent::windows {
std::string collect_windows_os_identity_json() { throw std::runtime_error("A fixture unexpectedly invoked real identity collection"); }
}
namespace {
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
std::string expiry() {
  FILETIME filetime{}; GetSystemTimeAsFileTime(&filetime);
  ULARGE_INTEGER value{}; value.LowPart = filetime.dwLowDateTime; value.HighPart = filetime.dwHighDateTime;
  value.QuadPart += 600ULL * 10000000ULL;
  filetime.dwLowDateTime = value.LowPart; filetime.dwHighDateTime = value.HighPart;
  SYSTEMTIME time{}; FileTimeToSystemTime(&filetime, &time);
  char output[32]{};
  std::snprintf(output, sizeof(output), "%04u-%02u-%02uT%02u:%02u:%02uZ", time.wYear, time.wMonth,
      time.wDay, time.wHour, time.wMinute, time.wSecond);
  return output;
}
security::scan_job job() {
  const auto* baseline = security::find_baseline("microsoft-windows-server-2025", "server");
  require(baseline != nullptr, "Compiled baseline missing");
  return {"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
      std::string(baseline->baseline_id), std::string(baseline->profile), std::string(baseline->manifest_sha256),
      baseline->controls.size(), expiry()};
}
int fixture_worker() {
  wchar_t mode[64]{};
  if (!GetEnvironmentVariableW(L"IPMS_TEST_SECURITY_FIXTURE", mode, 64)) return 1;
  wchar_t pid_file[32768]{};
  if (GetEnvironmentVariableW(L"IPMS_TEST_SECURITY_PID_FILE", pid_file, 32768)) {
    std::ofstream file{std::filesystem::path(pid_file)}; file << GetCurrentProcessId();
  }
  if (std::wstring_view(mode) == L"timeout") { Sleep(30000); return 1; }
  if (std::wstring_view(mode) == L"oversized") { std::cout << std::string(50000, 'x'); return 0; }
  if (std::wstring_view(mode) == L"malformed") { std::cout << "{}\n"; return 0; }
  std::string input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
  const auto task = security::parse_job(json::parse(input));
  const auto* baseline = security::find_baseline(task.baseline_id, task.profile);
  if (!baseline) return 1;
  json::array observations;
  for (const auto& control : baseline->controls) observations.emplace_back(security::observation(control.id, "unsupported"));
  auto pages = security::make_pages(task, *baseline, {{"os_build", "26100"}, {"product_type", 3},
      {"operating_system", "Windows Server 2025 Datacenter"}, {"join_state", "domain"}}, observations);
  if (std::wstring_view(mode) == L"wrong-scope") pages[0].at("system").as<json::object>()["product_type"] = 2;
  if (std::wstring_view(mode) == L"duplicate") pages[0].at("controls").as<json::array>()[1] = pages[0].at("controls").as<json::array>()[0];
  for (const auto& page : pages) std::cout << json::serialize(page, security::page_limits) << '\n';
  return std::wstring_view(mode) == L"nonzero" ? 1 : 0;
}
template <std::size_t N> auto bytes(const wchar_t (&value)[N]) {
  return std::span(reinterpret_cast<const std::uint8_t*>(value), sizeof(value));
}
void decoder_tests() {
  security::control_descriptor control{"typed-setting", security::probe_kind::registry_value, "machine", "SOFTWARE\\Policies\\Example", "Name", "dword"};
  const std::array<std::uint8_t, 4> dword{0xFF, 0xFF, 0xFF, 0xFF};
  auto value = decode_security_registry_value(control, REG_DWORD, dword);
  require(value.at("value").as<std::int64_t>() == 4294967295LL, "DWORD32 was signed or truncated");
  require(decode_security_registry_value(control, REG_QWORD, dword).at("read_status").as<std::string>() != "ok", "QWORD accepted as DWORD32");
  require(decode_security_registry_value(control, REG_DWORD, std::span(dword).first(3)).at("read_status").as<std::string>() != "ok", "Truncated DWORD accepted");
  control.value_type = "string";
  require(decode_security_registry_value(control, REG_SZ, bytes(L"example")).at("value").as<std::string>() == "example", "String decoding failed");
  require(decode_security_registry_value(control, REG_EXPAND_SZ, bytes(L"%PATH%")).at("value").as<std::string>() == "%PATH%", "Expanded data lost literal semantics");
  require(decode_security_registry_value(control, REG_SZ, bytes(L"a\0b")).at("read_status").as<std::string>() != "ok", "Embedded NUL accepted");
  const wchar_t malformed[]{0xD800, 0};
  require(decode_security_registry_value(control, REG_SZ, bytes(malformed)).at("read_status").as<std::string>() != "ok", "Invalid UTF16 accepted");
  control.value_type = "string_list";
  require(decode_security_registry_value(control, REG_MULTI_SZ, bytes(L"a\0b\0")).at("value").as<json::array>() == json::array{"a", "b"}, "Multi-string order changed");
  require(decode_security_registry_value(control, REG_MULTI_SZ, bytes(L"\0")).at("value").as<json::array>().empty(), "Empty multi-string was not preserved");
  require(decode_security_registry_value(control, REG_MULTI_SZ, bytes(L"a")).at("read_status").as<std::string>() != "ok", "Missing multi-string double terminator accepted");
  control.name = "MaximumPasswordAge";
  require(decode_security_account_duration(control, 90 * 86400).at("value").as<std::int64_t>() == 90,
          "Password-age seconds were not converted to exact INF days");
  auto forever = decode_security_account_duration(control, 0xFFFFFFFFU);
  require(forever.at("read_status").as<std::string>() == "unsupported" && forever.at("value").get_if<std::nullptr_t>(),
          "Infinite password age escaped the unsigned wire contract");
  require(decode_security_account_duration(control, 86401).at("read_status").as<std::string>() != "ok", "Fractional policy day was rounded");
  control.name = "LockoutDuration";
  require(decode_security_account_duration(control, 900).at("value").as<std::int64_t>() == 15,
          "Lockout seconds were not converted to exact INF minutes");
  require(decode_security_account_duration(control, 0).at("read_status").as<std::string>() == "unsupported",
          "Ambiguous unlimited lockout became a measured finite duration");
}
}  // namespace

int main(int argc, char** argv) {
  // These fixture switches exist only in this test executable, never in the
  // production Agent. Every observation is synthetic and no policy is read.
  if (argc == 2 && std::string_view(argv[1]) == "--collect-security-baseline") return fixture_worker();
  std::filesystem::path pid_path;
  try {
    decoder_tests();
    wchar_t temporary[32768]{};
    require(GetTempPathW(32768, temporary) != 0, "Test temporary path unavailable");
    pid_path = std::filesystem::path(temporary) / (L"ipms-security-fixture-" + std::to_wstring(GetCurrentProcessId()) + L".pid");
    SetEnvironmentVariableW(L"IPMS_TEST_SECURITY_PID_FILE", pid_path.c_str());
    SetEnvironmentVariableW(L"IPMS_TEST_SECURITY_FIXTURE", L"valid");
    const auto delivered = collect_security_baseline(job(), {}, std::chrono::seconds(3));
    require(delivered.error_code.empty() && delivered.pages.size() >= 10, "Valid complete multi-page subprocess result rejected");
    for (const auto* mode : {L"malformed", L"oversized", L"nonzero", L"wrong-scope", L"duplicate", L"timeout"}) {
      SetEnvironmentVariableW(L"IPMS_TEST_SECURITY_FIXTURE", mode);
      const auto began = std::chrono::steady_clock::now();
      const auto result = collect_security_baseline(job(), {}, std::chrono::milliseconds(400));
      require(!result.error_code.empty() && result.pages.empty(), "Failed or partial process leaked measurements");
      require(std::chrono::steady_clock::now() - began < std::chrono::seconds(3), "Process deadline did not bound native work");
      DWORD child_pid = 0;
      { std::ifstream input(pid_path); input >> child_pid; }
      if (child_pid) {
        const auto process = OpenProcess(SYNCHRONIZE, FALSE, child_pid);
        if (process) {
          const auto exited = WaitForSingleObject(process, 2000); CloseHandle(process);
          require(exited == WAIT_OBJECT_0, "Disposable child survived collection failure");
        }
      }
    }
    SetEnvironmentVariableW(L"IPMS_TEST_SECURITY_FIXTURE", L"timeout");
    std::atomic<unsigned> heartbeats{0};
    ipms::agent::periodic_worker heartbeat(std::chrono::milliseconds(10), [&](const auto&) { ++heartbeats; });
    const auto began = std::chrono::steady_clock::now();
    const auto cancelled = collect_security_baseline(job(), [&] { return std::chrono::steady_clock::now() - began > std::chrono::milliseconds(200); });
    heartbeat.stop();
    require(cancelled.error_code == "cancelled" && cancelled.pages.empty() && heartbeats.load() >= 3,
            "Hung scan ignored cancellation or starved heartbeat");
    auto unknown = job(); unknown.manifest_sha256.assign(64, 'b');
    require(collect_security_baseline(unknown).error_code == "unsupported_manifest", "Uncompiled manifest reached native reads");
    SetEnvironmentVariableW(L"IPMS_TEST_SECURITY_FIXTURE", nullptr);
    SetEnvironmentVariableW(L"IPMS_TEST_SECURITY_PID_FILE", nullptr);
    std::filesystem::remove(pid_path);
    std::cout << "PASS: typed registry decoder, complete pipe delivery, corruption/limits, cleanup, deadline, cancellation and heartbeat progress.\n";
    return 0;
  } catch (const std::exception& error) {
    SetEnvironmentVariableW(L"IPMS_TEST_SECURITY_FIXTURE", nullptr);
    SetEnvironmentVariableW(L"IPMS_TEST_SECURITY_PID_FILE", nullptr);
    if (!pid_path.empty()) { std::error_code ignored; std::filesystem::remove(pid_path, ignored); }
    std::cerr << error.what() << '\n'; return 1;
  }
}
