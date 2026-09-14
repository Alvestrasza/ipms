// File Name: windows_security_scan.cpp
// Version: v0.1.0
// Created: 2026-09-14
// Last Modified: 2026-09-14
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Compiled Windows policy reads isolated behind a bounded disposable process.
#include "ipms/agent/windows_security_scan.hpp"
#include "ipms/agent/windows_core_pack.hpp"

#include <windows.h>
#include <dsrole.h>
#include <lm.h>
#include <ntsecapi.h>
#include <objbase.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

namespace {
namespace security = ipms::agent::security;
namespace json = ipms::agent::management_json;
using security::control_descriptor;
constexpr wchar_t worker_argument[] = L" --collect-security-baseline";
constexpr int scope_changed_exit = 6;
constexpr int unsupported_manifest_exit = 7;
class handle {
 public:
  HANDLE value{};
  handle() = default;
  explicit handle(HANDLE raw) : value(raw) {}
  handle(const handle&) = delete;
  handle& operator=(const handle&) = delete;
  ~handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
  explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
  void close() { if (*this) CloseHandle(value); value = nullptr; }
};
std::wstring wide(std::string_view value) {
  if (value.size() > 2048 || value.find('\0') != std::string_view::npos) throw std::invalid_argument("Invalid native probe string.");
  if (value.empty()) return {};
  const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (!count) throw std::invalid_argument("Invalid native probe string.");
  std::wstring result(static_cast<std::size_t>(count), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count) != count)
    throw std::invalid_argument("Invalid native probe string.");
  return result;
}
std::string utf8(std::wstring_view value) {
  if (value.empty()) return {};
  if (value.size() > 2048) throw std::invalid_argument("Over-limit native observation.");
  const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (!count || count > 1024) throw std::invalid_argument("Invalid native observation.");
  std::string result(static_cast<std::size_t>(count), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count, nullptr, nullptr) != count)
    throw std::invalid_argument("Invalid native observation.");
  return result;
}
json::object failure(const control_descriptor& control, std::string_view status = "error") { return security::observation(control.id, status); }
json::object api_failure(const control_descriptor& control, DWORD status) {
  return failure(control, (status == ERROR_ACCESS_DENIED || status == ERROR_PRIVILEGE_NOT_HELD) ? "access_denied" :
      (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND || status == ERROR_SERVICE_DOES_NOT_EXIST) ? "missing" :
      (status == ERROR_MORE_DATA || status == ERROR_INSUFFICIENT_BUFFER) ? "limit" : "error");
}
json::object registry_value(const control_descriptor& control) {
  // Every path/name comes from the compiled, versioned descriptor catalog.
  if (control.path.empty() || control.path.front() == '\\' || control.path.starts_with("HKEY") ||
      control.name.starts_with("**")) return failure(control, "unsupported");
  std::array<std::uint8_t, 4096> buffer{};
  DWORD bytes = static_cast<DWORD>(buffer.size()), type = 0;
  const auto path = wide(control.path), name = wide(control.name);
  const auto status = RegGetValueW(HKEY_LOCAL_MACHINE, path.c_str(), name.c_str(),
      RRF_RT_ANY | RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY | RRF_ZEROONFAILURE, &type, buffer.data(), &bytes);
  if (status != ERROR_SUCCESS) return api_failure(control, status);
  if (bytes > buffer.size()) return failure(control, "limit");
  return ipms::agent::windows::decode_security_registry_value(control, type, std::span(buffer).first(bytes));
}
json::object audit_policy(const control_descriptor& control) {
  const auto text = wide(control.path.empty() ? control.name : control.path);
  GUID id{};
  if (FAILED(CLSIDFromString(text.c_str(), &id))) return failure(control, "unsupported");
  PAUDIT_POLICY_INFORMATION information = nullptr;
  if (!AuditQuerySystemPolicy(&id, 1, &information)) return api_failure(control, GetLastError());
  struct cleanup { PAUDIT_POLICY_INFORMATION value; ~cleanup() { if (value) AuditFree(value); } } release{information};
  if (!information || !IsEqualGUID(information->AuditSubCategoryGuid, id)) return failure(control);
  const auto bits = information->AuditingInformation;
  // POLICY_AUDIT_EVENT_NONE is a distinct API flag; CSV represents it as 0.
  if (bits == POLICY_AUDIT_EVENT_NONE) return security::observation(control.id, "ok", 0);
  if (bits & ~(POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE)) return failure(control);
  return security::observation(control.id, "ok", bits);
}
json::object user_right(const control_descriptor& control) {
  LSA_OBJECT_ATTRIBUTES attributes{};
  attributes.Length = sizeof(attributes);
  LSA_HANDLE policy = nullptr;
  auto status = LsaOpenPolicy(nullptr, &attributes, POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION, &policy);
  if (status != 0) return api_failure(control, LsaNtStatusToWinError(status));
  struct policy_cleanup { LSA_HANDLE value; ~policy_cleanup() { LsaClose(value); } } close{policy};
  auto name = wide(control.name);
  LSA_UNICODE_STRING right{};
  right.Buffer = name.data(); right.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t)); right.MaximumLength = right.Length;
  PVOID data = nullptr;
  ULONG count = 0;
  status = LsaEnumerateAccountsWithUserRight(policy, &right, &data, &count);
  struct memory_cleanup { PVOID value; ~memory_cleanup() { if (value) LsaFreeMemory(value); } } release{data};
  if (status == static_cast<NTSTATUS>(0x8000001A)) return security::observation(control.id, "ok", json::array{});
  if (status != 0) return api_failure(control, LsaNtStatusToWinError(status));
  if (count > 32) return failure(control, "limit");
  if (count && !data) return failure(control);
  std::set<std::string> sids;
  const auto* items = static_cast<PLSA_ENUMERATION_INFORMATION>(data);
  for (ULONG index = 0; index < count; ++index) {
    LPWSTR sid = nullptr;
    if (!IsValidSid(items[index].Sid) || !ConvertSidToStringSidW(items[index].Sid, &sid)) return failure(control);
    struct local_cleanup { LPWSTR value; ~local_cleanup() { LocalFree(value); } } free_sid{sid};
    sids.insert(utf8(sid));
  }
  json::array values;
  for (const auto& sid : sids) values.emplace_back(sid);
  return security::observation(control.id, "ok", std::move(values));
}
json::object account_policy(const control_descriptor& control, const json::object& system) {
  // Domain and resultant per-user policies require separate evidence. Even a
  // local API call on a DC reads domain state, not a local SAM policy.
  if (system.at("product_type").as<std::int64_t>() == 2) return failure(control, "unsupported");
  const bool lockout = control.name == "LockoutBadCount" || control.name == "ResetLockoutCount" || control.name == "LockoutDuration";
  const bool password = control.name == "MinimumPasswordAge" || control.name == "MaximumPasswordAge" ||
      control.name == "MinimumPasswordLength" || control.name == "PasswordHistorySize";
  if (!lockout && !password) return failure(control, "unsupported");
  LPBYTE data = nullptr;
  const auto status = NetUserModalsGet(nullptr, lockout ? 3 : 0, &data);
  struct cleanup { LPBYTE value; ~cleanup() { if (value) NetApiBufferFree(value); } } release{data};
  if (status != NERR_Success) return api_failure(control, status);
  if (!data) return failure(control);
  DWORD value = 0, divisor = 1;
  if (lockout) {
    const auto* info = reinterpret_cast<USER_MODALS_INFO_3*>(data);
    if (control.name == "LockoutBadCount") value = info->usrmod3_lockout_threshold;
    else { value = control.name == "ResetLockoutCount" ? info->usrmod3_lockout_observation_window : info->usrmod3_lockout_duration; divisor = 60; }
  } else {
    const auto* info = reinterpret_cast<USER_MODALS_INFO_0*>(data);
    if (control.name == "MinimumPasswordLength") value = info->usrmod0_min_passwd_len;
    else if (control.name == "PasswordHistorySize") value = info->usrmod0_password_hist_len;
    else { value = control.name == "MinimumPasswordAge" ? info->usrmod0_min_passwd_age : info->usrmod0_max_passwd_age; divisor = 86400; }
  }
  if (divisor > 1) return ipms::agent::windows::decode_security_account_duration(control, value);
  return security::observation(control.id, "ok", value);
}
json::object service_start(const control_descriptor& control) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) return api_failure(control, GetLastError());
  struct service_cleanup { SC_HANDLE value; ~service_cleanup() { if (value) CloseServiceHandle(value); } } close_manager{manager};
  SC_HANDLE service = OpenServiceW(manager, wide(control.name).c_str(), SERVICE_QUERY_CONFIG);
  if (!service) return api_failure(control, GetLastError());
  service_cleanup close_service{service};
  alignas(QUERY_SERVICE_CONFIGW) std::array<std::uint8_t, 8192> data{};
  DWORD required = 0;
  if (!QueryServiceConfigW(service, reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(data.data()), static_cast<DWORD>(data.size()), &required))
    return api_failure(control, GetLastError());
  const auto start_type = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(data.data())->dwStartType;
  if (start_type > SERVICE_DISABLED) return failure(control);
  return security::observation(control.id, "ok", start_type);
}
json::object read_control(const control_descriptor& control, const json::object& system) {
  try {
    if (control.scope != "machine") return failure(control, "unsupported");
    switch (control.probe) {
      case security::probe_kind::registry_value: return registry_value(control);
      case security::probe_kind::audit_policy: return audit_policy(control);
      case security::probe_kind::user_right: return user_right(control);
      case security::probe_kind::account_policy: return account_policy(control, system);
      case security::probe_kind::service_start: return service_start(control);
      default: return failure(control, "unsupported");
    }
  } catch (...) { return failure(control, "limit"); }
}
json::object read_system() {
  // This function uses the exact inventory OS-name normalizer. WMI activation
  // and all local RPC calls remain inside the disposable process deadline.
  auto system = json::parse(ipms::agent::windows::collect_windows_os_identity_json()).as<json::object>();
  std::string join = "unknown";
  PBYTE raw = nullptr;
  const auto result = DsRoleGetPrimaryDomainInformation(nullptr, DsRolePrimaryDomainInfoBasic, &raw);
  struct cleanup { PBYTE value; ~cleanup() { if (value) DsRoleFreeMemory(value); } } release{raw};
  if (result == ERROR_SUCCESS && raw) {
    const auto role = reinterpret_cast<DSROLE_PRIMARY_DOMAIN_INFO_BASIC*>(raw)->MachineRole;
    if (role == DsRole_RoleStandaloneWorkstation || role == DsRole_RoleStandaloneServer) join = "workgroup";
    else if (role == DsRole_RoleMemberWorkstation || role == DsRole_RoleMemberServer ||
             role == DsRole_RoleBackupDomainController || role == DsRole_RolePrimaryDomainController) join = "domain";
  }
  system["join_state"] = join;
  return system;
}
void enable_audit_read_privilege() {
  // Changes only this disposable process token, never machine audit policy.
  handle token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token.value)) return;
  TOKEN_PRIVILEGES privileges{};
  privileges.PrivilegeCount = 1;
  if (!LookupPrivilegeValueW(nullptr, SE_SECURITY_NAME, &privileges.Privileges[0].Luid)) return;
  privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(token.value, FALSE, &privileges, 0, nullptr, nullptr);
}
class startup_attributes {
 public:
  std::vector<std::uint8_t> storage;
  LPPROC_THREAD_ATTRIBUTE_LIST list{};
  bool initialize(HANDLE input, HANDLE output, HANDLE null_device) {
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    if (!bytes) return false;
    storage.resize(bytes); list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(list, 1, 0, &bytes)) { list = nullptr; return false; }
    inherited = {input, output, null_device};
    return UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), sizeof(inherited), nullptr, nullptr) != FALSE;
  }
  ~startup_attributes() { if (list) DeleteProcThreadAttributeList(list); }
 private:
  std::array<HANDLE, 3> inherited{};
};
}  // namespace

namespace ipms::agent::windows {
json::object decode_security_account_duration(const control_descriptor& control, std::uint32_t seconds) {
  const bool password = control.name == "MinimumPasswordAge" || control.name == "MaximumPasswordAge";
  const bool lockout = control.name == "ResetLockoutCount" || control.name == "LockoutDuration";
  if (!password && !lockout) return failure(control, "unsupported");
  // NetUserModalsGet reports seconds; the security-template values use days
  // and minutes. TIMEQ_FOREVER has a signed INF representation outside the
  // unsigned wire contract. Preserve that uncertainty rather than emit -1,
  // coerce infinity to a duration, or reject an otherwise usable page.
  if (seconds == TIMEQ_FOREVER || (seconds == 0 &&
      (control.name == "MaximumPasswordAge" || control.name == "LockoutDuration"))) return failure(control, "unsupported");
  const std::uint32_t divisor = password ? 86400U : 60U;
  if (seconds % divisor) return failure(control);
  return security::observation(control.id, "ok", seconds / divisor);
}

json::object decode_security_registry_value(const control_descriptor& control, std::uint32_t type, std::span<const std::uint8_t> data) {
  try {
    if (type == REG_DWORD && control.value_type == "dword") {
      if (data.size() != sizeof(DWORD)) return failure(control);
      DWORD value = 0; std::memcpy(&value, data.data(), sizeof(value));
      return security::observation(control.id, "ok", value);
    }
    const bool single = (type == REG_SZ || type == REG_EXPAND_SZ) && control.value_type == "string";
    const bool multiple = type == REG_MULTI_SZ && control.value_type == "string_list";
    if (!single && !multiple) return failure(control, "unsupported");
    if (data.empty() || data.size() % sizeof(wchar_t) || data.size() > 4096) return failure(control);
    std::wstring text(data.size() / sizeof(wchar_t), L'\0');
    std::memcpy(text.data(), data.data(), data.size());
    if (text.back() != L'\0') return failure(control);
    if (single) {
      text.pop_back();
      if (text.find(L'\0') != std::wstring::npos) return failure(control);
      return security::observation(control.id, "ok", utf8(text));
    }
    if (text.size() < 2 || text[text.size() - 2] != L'\0') return failure(control);
    json::array items;
    std::size_t start = 0;
    while (start < text.size() - 1) {
      const auto end = text.find(L'\0', start);
      if (end == start) { if (start != text.size() - 2 || !items.empty()) return failure(control); break; }
      if (end == std::wstring::npos || items.size() >= 32) return failure(control, "limit");
      items.emplace_back(utf8(std::wstring_view(text).substr(start, end - start)));
      start = end + 1;
    }
    return security::observation(control.id, "ok", std::move(items));
  } catch (...) { return failure(control, "limit"); }
}

int run_security_baseline_worker() {
  try {
    const HANDLE source = GetStdHandle(STD_INPUT_HANDLE), destination = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!source || source == INVALID_HANDLE_VALUE || !destination || destination == INVALID_HANDLE_VALUE) return 1;
    std::string input;
    for (;;) {
      std::array<char, 1024> buffer{}; DWORD read = 0;
      if (!ReadFile(source, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
        if (GetLastError() == ERROR_BROKEN_PIPE) break;
        return 1;
      }
      if (!read) break;
      if (input.size() + read > 4096) return 1;
      input.append(buffer.data(), read);
    }
    const auto job = security::parse_job(json::parse(input));
    const auto* baseline = security::find_baseline(job.baseline_id, job.profile);
    if (!baseline || !security::matches_manifest(job, *baseline)) return unsupported_manifest_exit;
    if (!security::job_unexpired(job)) return 1;
    const auto system = read_system();
    if (!security::scope_matches(*baseline, system)) return scope_changed_exit;
    enable_audit_read_privilege();
    json::array controls;
    for (const auto& control : baseline->controls) controls.emplace_back(read_control(control, system));
    const auto pages = security::make_pages(job, *baseline, system, controls);
    for (const auto& page : pages) {
      const auto output = json::serialize(page, security::page_limits) + "\n";
      DWORD written = 0;
      if (!WriteFile(destination, output.data(), static_cast<DWORD>(output.size()), &written, nullptr) || written != output.size()) return 1;
    }
    return 0;
  } catch (...) { return 1; }
}

security_scan_result collect_security_baseline(const security::scan_job& job, const std::function<bool()>& cancelled,
                                               std::chrono::milliseconds timeout) {
  auto failed = [](std::string code = "collection_failed") { return security_scan_result{{}, std::move(code)}; };
  try {
    if (cancelled && cancelled()) return failed("cancelled");
    const auto* baseline = security::find_baseline(job.baseline_id, job.profile);
    if (!baseline || !security::matches_manifest(job, *baseline)) return failed("unsupported_manifest");
    if (timeout.count() <= 0 || timeout > std::chrono::seconds(30) || !security::job_unexpired(job)) return failed();
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<wchar_t> executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!length || length >= executable.size()) return failed();
    const std::wstring path(executable.data(), length);
    if (path.find(L'"') != std::wstring::npos) return failed();
    std::wstring command = L"\"" + path + L"\"" + worker_argument;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    handle input_reader, input_writer, output_reader, output_writer;
    if (!CreatePipe(&input_reader.value, &input_writer.value, &attributes, 4096) ||
        !SetHandleInformation(input_writer.value, HANDLE_FLAG_INHERIT, 0) ||
        !CreatePipe(&output_reader.value, &output_writer.value, &attributes, 16384) ||
        !SetHandleInformation(output_reader.value, HANDLE_FLAG_INHERIT, 0)) return failed();
    handle null_device(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    handle process_job(CreateJobObjectW(nullptr, nullptr));
    if (!null_device || !process_job) return failed();
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = 128 * 1024 * 1024;
    if (!SetInformationJobObject(process_job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return failed();
    startup_attributes inherited;
    if (!inherited.initialize(input_reader.value, output_writer.value, null_device.value)) return failed();
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input_reader.value; startup.StartupInfo.hStdOutput = output_writer.value; startup.StartupInfo.hStdError = null_device.value;
    startup.lpAttributeList = inherited.list;
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &child)) return failed();
    handle process(child.hProcess), thread(child.hThread);
    if (!AssignProcessToJobObject(process_job.value, process.value)) { TerminateProcess(process.value, 1); return failed(); }
    const auto input = json::serialize(security::job_document(job));
    if (input.size() > 4096) return failed();
    DWORD written = 0;
    if (!WriteFile(input_writer.value, input.data(), static_cast<DWORD>(input.size()), &written, nullptr) || written != input.size()) return failed();
    input_writer.close();
    if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) return failed();
    input_reader.close(); output_writer.close();
    std::string pending_line;
    std::size_t bytes_seen = 0;
    std::vector<json::object> pages;
    for (;;) {
      if (cancelled && cancelled()) return failed("cancelled");
      if (std::chrono::steady_clock::now() >= deadline || !security::job_unexpired(job)) return failed();
      DWORD available = 0;
      const BOOL peeked = PeekNamedPipe(output_reader.value, nullptr, 0, nullptr, &available, nullptr);
      if (!peeked && GetLastError() != ERROR_BROKEN_PIPE) return failed();
      if (available) {
        std::array<char, 8192> buffer{}; DWORD read = 0;
        if (!ReadFile(output_reader.value, buffer.data(), std::min<DWORD>(available, static_cast<DWORD>(buffer.size())), &read, nullptr) || !read) return failed();
        bytes_seen += read;
        if (bytes_seen > security::max_output_bytes) return failed();
        for (DWORD index = 0; index < read; ++index) {
          if (buffer[index] == '\n') {
            if (pending_line.empty() || pages.size() >= security::max_pages) return failed();
            pages.push_back(json::parse(pending_line, security::page_limits).as<json::object>());
            pending_line.clear();
          } else {
            if (pending_line.size() >= security::max_page_bytes) return failed();
            pending_line.push_back(buffer[index]);
          }
        }
      } else {
        const auto wait = WaitForSingleObject(process.value, 0);
        if (wait == WAIT_OBJECT_0) {
          DWORD remaining = 0;
          const auto final_peek = PeekNamedPipe(output_reader.value, nullptr, 0, nullptr, &remaining, nullptr);
          if (!final_peek && GetLastError() != ERROR_BROKEN_PIPE) return failed();
          if (remaining) continue;
          DWORD exit_code = 1;
          if (!GetExitCodeProcess(process.value, &exit_code)) return failed();
          if (exit_code == scope_changed_exit) return failed("scope_changed");
          if (exit_code == unsupported_manifest_exit) return failed("unsupported_manifest");
          if (exit_code != 0 || !pending_line.empty()) return failed();
          security::validate_pages(job, *baseline, pages);
          return {std::move(pages), ""};
        }
        if (wait != WAIT_TIMEOUT) return failed();
      }
      WaitForSingleObject(process.value, 10);
    }
  } catch (...) { return failed(); }
}
}  // namespace ipms::agent::windows
