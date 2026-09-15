// File Name: windows_group_policy.cpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Read-only RSoP and applied-CSE history behind a fixed disposable process.
#include "ipms/agent/windows_group_policy.hpp"
#include "ipms/agent/management_json.hpp"

#include <windows.h>
#include <dsrole.h>
#include <userenv.h>
#include <wbemidl.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdio>
#include <cwchar>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>

namespace {
namespace json = ipms::agent::management_json;
using namespace ipms::agent::windows;
constexpr std::size_t max_gpos = 256, max_extensions = 64, max_gpo_extensions = 32;
constexpr std::size_t max_bytes = 64 * 1024;
constexpr json::limits output_limits{max_bytes, 4, 4096, 512};
constexpr wchar_t worker_argument[] = L" --collect-windows-group-policy";
constexpr std::string_view zero_guid = "00000000-0000-0000-0000-000000000000";

struct read_error { std::string status; };
class handle {
 public:
  HANDLE value{};
  handle() = default;
  explicit handle(HANDLE raw) : value(raw) {}
  handle(const handle&) = delete;
  handle& operator=(const handle&) = delete;
  ~handle() { close(); }
  explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
  void close() { if (*this) CloseHandle(value); value = nullptr; }
};
struct variant {
  VARIANT value{};
  variant() { VariantInit(&value); }
  ~variant() { VariantClear(&value); }
};
struct bstr {
  BSTR value{};
  explicit bstr(const wchar_t* input) : value(SysAllocString(input)) {
    if (!value) throw read_error{"unavailable"};
  }
  ~bstr() { SysFreeString(value); }
};

std::string lower_ascii(std::string value) {
  for (auto& ch : value) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
  return value;
}
std::string uuid(std::string text, bool allow_zero = false) {
  if (text.size() == 38 && text.front() == '{' && text.back() == '}') text = text.substr(1, 36);
  text = lower_ascii(std::move(text));
  if (text.size() != 36) return {};
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) { if (text[i] != '-') return {}; }
    else if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return {};
  }
  return allow_zero || text != zero_guid ? text : std::string();
}
std::string dns_name(std::string value) {
  value = lower_ascii(std::move(value));
  if (value.empty() || value.size() > 253 || value.find('.') == std::string::npos) return {};
  if (std::all_of(value.begin(), value.end(), [](const char ch) { return ch == '.' || (ch >= '0' && ch <= '9'); })) return {};
  std::size_t start = 0;
  while (start < value.size()) {
    const auto dot = value.find('.', start);
    const auto end = dot == std::string::npos ? value.size() : dot;
    if (end == start || end - start > 63 || value[start] == '-' || value[end - 1] == '-') return {};
    for (auto i = start; i < end; ++i)
      if (!((value[i] >= 'a' && value[i] <= 'z') || (value[i] >= '0' && value[i] <= '9') || value[i] == '-')) return {};
    if (dot == std::string::npos) return value;
    start = dot + 1;
  }
  return {};
}
std::string utf8(std::wstring_view input, std::size_t limit = 2048) {
  if (input.size() > limit || input.find(L'\0') != std::wstring_view::npos) throw read_error{"incomplete"};
  if (input.empty()) return {};
  const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(),
      static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
  if (!count || static_cast<std::size_t>(count) > limit) throw read_error{"incomplete"};
  std::string output(static_cast<std::size_t>(count), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
      output.data(), count, nullptr, nullptr) != count) throw read_error{"incomplete"};
  return output;
}
std::string bounded_string(const wchar_t* input, std::size_t limit = 2048) {
  return input ? utf8(std::wstring_view(input, wcsnlen_s(input, limit + 1)), limit) : std::string();
}
std::string guid_text(const GUID& value) {
  std::array<wchar_t, 39> text{};
  if (StringFromGUID2(value, text.data(), static_cast<int>(text.size())) != 39) return {};
  return uuid(bounded_string(text.data(), 38));
}
std::string utc_string(const SYSTEMTIME& time) {
  std::array<char, 21> output{};
  const auto count = std::snprintf(output.data(), output.size(), "%04u-%02u-%02uT%02u:%02u:%02uZ",
      static_cast<unsigned>(time.wYear), static_cast<unsigned>(time.wMonth), static_cast<unsigned>(time.wDay),
      static_cast<unsigned>(time.wHour), static_cast<unsigned>(time.wMinute), static_cast<unsigned>(time.wSecond));
  return count == 20 ? std::string(output.data(), 20) : std::string();
}
std::string now_utc() { SYSTEMTIME time{}; GetSystemTime(&time); return utc_string(time); }
unsigned number(std::string_view value) {
  unsigned result = 0;
  for (const auto ch : value) {
    if (ch < '0' || ch > '9') throw std::invalid_argument("Incomplete timestamp");
    result = result * 10U + static_cast<unsigned>(ch - '0');
  }
  return result;
}
std::optional<std::uint64_t> utc_ticks(std::string_view text) {
  try {
    if (text.size() != 20 || text[4] != '-' || text[7] != '-' || text[10] != 'T' ||
        text[13] != ':' || text[16] != ':' || text[19] != 'Z') return {};
    SYSTEMTIME time{};
    time.wYear = static_cast<WORD>(number(text.substr(0, 4)));
    time.wMonth = static_cast<WORD>(number(text.substr(5, 2)));
    time.wDay = static_cast<WORD>(number(text.substr(8, 2)));
    time.wHour = static_cast<WORD>(number(text.substr(11, 2)));
    time.wMinute = static_cast<WORD>(number(text.substr(14, 2)));
    time.wSecond = static_cast<WORD>(number(text.substr(17, 2)));
    FILETIME file{}; SYSTEMTIME roundtrip{};
    if (time.wYear < 1601 || !SystemTimeToFileTime(&time, &file) || !FileTimeToSystemTime(&file, &roundtrip) ||
        utc_string(roundtrip) != text) return {};
    ULARGE_INTEGER ticks{}; ticks.LowPart = file.dwLowDateTime; ticks.HighPart = file.dwHighDateTime;
    return ticks.QuadPart;
  } catch (...) { return {}; }
}
std::optional<std::uint64_t> wmi_ticks(std::string_view timestamp) {
  try {
    if (timestamp.size() != 25 || timestamp[14] != '.' || (timestamp[21] != '+' && timestamp[21] != '-')) return {};
    const auto micros = number(timestamp.substr(15, 6));
    const auto text = std::string(timestamp.substr(0, 4)) + "-" + std::string(timestamp.substr(4, 2)) + "-" +
        std::string(timestamp.substr(6, 2)) + "T" + std::string(timestamp.substr(8, 2)) + ":" +
        std::string(timestamp.substr(10, 2)) + ":" + std::string(timestamp.substr(12, 2)) + "Z";
    const auto raw = utc_ticks(text);
    const auto offset = static_cast<std::uint64_t>(number(timestamp.substr(22, 3))) * 60ULL * 10000000ULL;
    if (!raw || (timestamp[21] == '+' && *raw < offset)) return {};
    return (timestamp[21] == '+' ? *raw - offset : *raw + offset) + micros * 10ULL;
  } catch (...) { return {}; }
}
json::object empty_evidence(std::string_view status = "unavailable", std::string_view observed = {}) {
  return {{"schema_version", "1"}, {"source", "windows-rsop-computer"}, {"scope", "computer"},
      {"status", status}, {"observed_at", observed.empty() ? now_utc() : std::string(observed)},
      {"domain_dns", nullptr}, {"domain_guid", nullptr}, {"gpos", json::array{}}};
}
std::string empty_json(std::string_view status = "unavailable", std::string_view observed = {}) {
  return json::serialize(empty_evidence(status, observed), output_limits);
}
bool directory_matches(std::string path, const std::string& guid, const std::string& domain) {
  if (path.empty() || path.size() > 2048 || path.find('\0') != std::string::npos) return false;
  path = lower_ascii(std::move(path));
  if (path.starts_with("ldap://")) {
    path.erase(0, 7);
    if (!path.starts_with("cn=")) {
      const auto slash = path.find('/');
      if (slash == std::string::npos || dns_name(path.substr(0, slash)).empty()) return false;
      path.erase(0, slash + 1);
    }
  }
  std::string expected = "cn={" + guid + "},cn=policies,cn=system";
  for (std::size_t start = 0; start < domain.size();) {
    const auto dot = domain.find('.', start);
    const auto end = dot == std::string::npos ? domain.size() : dot;
    expected += ",dc=" + domain.substr(start, end - start);
    start = end + 1;
  }
  return path == expected;
}
template <typename T, typename Key> void sort_unique(std::vector<T>& rows, Key key) {
  std::sort(rows.begin(), rows.end(), [&](const auto& left, const auto& right) { return key(left) < key(right); });
  for (std::size_t i = 1; i < rows.size(); ++i)
    if (key(rows[i - 1]) == key(rows[i])) throw read_error{"incomplete"};
}
void normalize_snapshot(group_policy_snapshot& snapshot) {
  if (snapshot.gpos.size() > max_gpos || snapshot.extensions.size() > max_extensions ||
      snapshot.history.size() > max_extensions) throw read_error{"incomplete"};
  if (!snapshot.domain_joined) {
    if (!snapshot.domain_dns.empty() || !snapshot.domain_guid.empty() || !snapshot.gpos.empty() ||
        !snapshot.extensions.empty() || !snapshot.history.empty()) throw read_error{"incomplete"};
    return;
  }
  snapshot.domain_dns = dns_name(std::move(snapshot.domain_dns));
  snapshot.domain_guid = uuid(std::move(snapshot.domain_guid));
  if (snapshot.domain_dns.empty() || snapshot.domain_guid.empty()) throw read_error{"incomplete"};
  std::set<std::string> used_extensions;
  for (auto& gpo : snapshot.gpos) {
    gpo.guid = uuid(std::move(gpo.guid));
    if (gpo.guid.empty() || gpo.extension_ids.size() > max_gpo_extensions ||
        gpo.directory_path.size() > 2048) throw read_error{"incomplete"};
    for (auto& extension : gpo.extension_ids) {
      extension = uuid(std::move(extension));
      if (extension.empty()) throw read_error{"incomplete"};
      used_extensions.insert(extension);
    }
    sort_unique(gpo.extension_ids, [](const auto& value) { return value; });
  }
  if (used_extensions.size() > max_extensions) throw read_error{"incomplete"};
  sort_unique(snapshot.gpos, [](const auto& value) { return value.guid; });
  for (auto& extension : snapshot.extensions) {
    // Preserve an infrastructure record using the zero GUID, if present;
    // it cannot become a GPO or a required client-side extension identity.
    extension.guid = uuid(std::move(extension.guid), true);
    if (extension.guid.empty() || extension.begin_time.size() > 25 || extension.end_time.size() > 25)
      throw read_error{"incomplete"};
  }
  sort_unique(snapshot.extensions, [](const auto& value) { return value.guid; });
  for (auto& history : snapshot.history) {
    history.extension_guid = uuid(std::move(history.extension_guid));
    if (history.extension_guid.empty() || history.gpos.size() > max_gpos) throw read_error{"incomplete"};
    for (auto& gpo : history.gpos) {
      gpo.guid = uuid(std::move(gpo.guid));
      if (gpo.guid.empty() || gpo.directory_path.size() > 2048) throw read_error{"incomplete"};
    }
    sort_unique(history.gpos, [](const auto& value) { return value.guid; });
  }
  sort_unique(snapshot.history, [](const auto& value) { return value.extension_guid; });
}

std::string wmi_string(IWbemClassObject* row, const wchar_t* property, std::size_t limit = 2048) {
  variant item;
  if (FAILED(row->Get(property, 0, &item.value, nullptr, nullptr))) throw read_error{"incomplete"};
  if (item.value.vt == VT_NULL || item.value.vt == VT_EMPTY) return {};
  if (item.value.vt != VT_BSTR || !item.value.bstrVal) throw read_error{"incomplete"};
  return utf8(std::wstring_view(item.value.bstrVal, SysStringLen(item.value.bstrVal)), limit);
}
std::uint32_t wmi_uint(IWbemClassObject* row, const wchar_t* property) {
  variant item; CIMTYPE type{};
  if (FAILED(row->Get(property, 0, &item.value, &type, nullptr)) || type != CIM_UINT32) throw read_error{"incomplete"};
  if (item.value.vt == VT_UI4) return item.value.ulVal;
  // WMI represents CIM_UINT32 with VT_I4 as well; preserve all 32 bits.
  if (item.value.vt == VT_I4) return static_cast<std::uint32_t>(item.value.lVal);
  throw read_error{"incomplete"};
}
bool wmi_bool(IWbemClassObject* row, const wchar_t* property) {
  variant item;
  if (FAILED(row->Get(property, 0, &item.value, nullptr, nullptr)) || item.value.vt != VT_BOOL ||
      (item.value.boolVal != VARIANT_TRUE && item.value.boolVal != VARIANT_FALSE)) throw read_error{"incomplete"};
  return item.value.boolVal == VARIANT_TRUE;
}
std::vector<std::string> wmi_strings(IWbemClassObject* row, const wchar_t* property) {
  variant item;
  if (FAILED(row->Get(property, 0, &item.value, nullptr, nullptr))) throw read_error{"incomplete"};
  if (item.value.vt == VT_NULL || item.value.vt == VT_EMPTY) return {};
  if (item.value.vt != (VT_ARRAY | VT_BSTR) || !item.value.parray || SafeArrayGetDim(item.value.parray) != 1)
    throw read_error{"incomplete"};
  LONG first{}, last{};
  if (FAILED(SafeArrayGetLBound(item.value.parray, 1, &first)) || FAILED(SafeArrayGetUBound(item.value.parray, 1, &last)) ||
      static_cast<std::int64_t>(last) - first + 1 > static_cast<std::int64_t>(max_gpo_extensions)) throw read_error{"incomplete"};
  std::vector<std::string> values;
  for (LONG index = first; index <= last; ++index) {
    BSTR text{};
    if (FAILED(SafeArrayGetElement(item.value.parray, &index, &text)) || !text) throw read_error{"incomplete"};
    struct cleanup { BSTR value; ~cleanup() { SysFreeString(value); } } release{text};
    values.push_back(utf8(std::wstring_view(text, SysStringLen(text)), 38));
    if (index == LONG_MAX) break;
  }
  return values;
}
template <typename Read> void query(IWbemServices* services, const wchar_t* statement, std::size_t limit, Read read) {
  bstr language(L"WQL"), text(statement);
  Microsoft::WRL::ComPtr<IEnumWbemClassObject> rows;
  if (FAILED(services->ExecQuery(language.value, text.value, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
      nullptr, &rows)) || !rows) throw read_error{"unavailable"};
  std::size_t count = 0;
  for (;;) {
    Microsoft::WRL::ComPtr<IWbemClassObject> row;
    ULONG returned = 0;
    const auto result = rows->Next(1000, 1, row.GetAddressOf(), &returned);
    if (result == WBEM_S_FALSE && returned == 0) return;
    if (result != WBEM_S_NO_ERROR || returned != 1 || !row || ++count > limit) throw read_error{"incomplete"};
    read(row.Get());
  }
}
void read_domain(group_policy_snapshot& snapshot) {
  PBYTE data{};
  const auto result = DsRoleGetPrimaryDomainInformation(nullptr, DsRolePrimaryDomainInfoBasic, &data);
  struct cleanup { PBYTE value; ~cleanup() { if (value) DsRoleFreeMemory(value); } } release{data};
  if (result != ERROR_SUCCESS || !data) throw read_error{"unavailable"};
  const auto& info = *reinterpret_cast<DSROLE_PRIMARY_DOMAIN_INFO_BASIC*>(data);
  if (info.MachineRole == DsRole_RoleStandaloneServer || info.MachineRole == DsRole_RoleStandaloneWorkstation) return;
  if (info.MachineRole != DsRole_RoleMemberServer && info.MachineRole != DsRole_RoleMemberWorkstation &&
      info.MachineRole != DsRole_RolePrimaryDomainController && info.MachineRole != DsRole_RoleBackupDomainController)
    throw read_error{"unavailable"};
  snapshot.domain_joined = true;
  if (!(info.Flags & DSROLE_PRIMARY_DOMAIN_GUID_PRESENT)) throw read_error{"unavailable"};
  snapshot.domain_dns = dns_name(bounded_string(info.DomainNameDns, 253));
  snapshot.domain_guid = guid_text(info.DomainGuid);
  if (snapshot.domain_dns.empty() || snapshot.domain_guid.empty()) throw read_error{"unavailable"};
}
void require_logging_enabled() {
  for (const auto* path : {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"}) {
    DWORD value = 0, bytes = sizeof(value);
    const auto result = RegGetValueW(HKEY_LOCAL_MACHINE, path, L"RSoPLogging",
        RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &value, &bytes);
    if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) continue;
    // Microsoft GroupPolicy.admx: Turn off RSoP logging writes 0; enabled logging is 1.
    if (result != ERROR_SUCCESS || bytes != sizeof(value) || value != 1) throw read_error{"unavailable"};
  }
}
group_policy_snapshot read_snapshot(IWbemServices* services) {
  group_policy_snapshot snapshot;
  read_domain(snapshot);
  if (!snapshot.domain_joined) return snapshot;
  require_logging_enabled();
  query(services, L"SELECT extensionGuid,beginTime,endTime,loggingStatus,error FROM RSOP_ExtensionStatus", max_extensions,
      [&](IWbemClassObject* row) {
        snapshot.extensions.push_back({wmi_string(row, L"extensionGuid", 38), wmi_string(row, L"beginTime", 25),
            wmi_string(row, L"endTime", 25), wmi_uint(row, L"loggingStatus"), wmi_uint(row, L"error")});
      });
  query(services, L"SELECT id,guidName,version,enabled,accessDenied,filterAllowed,extensionIds FROM RSOP_GPO", max_gpos,
      [&](IWbemClassObject* row) {
        auto guid = wmi_string(row, L"guidName", 38);
        auto path = wmi_string(row, L"id");
        // Local policy has no AD GUID and cannot map to a deployed domain GPO.
        if (guid == "LocalGPO" && path == "LocalGPO") return;
        snapshot.gpos.push_back({std::move(guid), std::move(path), wmi_uint(row, L"version"),
            wmi_bool(row, L"enabled"), wmi_bool(row, L"accessDenied"), wmi_bool(row, L"filterAllowed"),
            wmi_strings(row, L"extensionIds")});
      });
  normalize_snapshot(snapshot);
  std::set<std::string> required;
  for (const auto& gpo : snapshot.gpos) for (const auto& extension : gpo.extension_ids) required.insert(extension);
  for (const auto& extension : required) {
    GUID extension_guid{};
    const std::wstring text(extension.begin(), extension.end());
    if (FAILED(CLSIDFromString((L"{" + text + L"}").c_str(), &extension_guid))) throw read_error{"incomplete"};
    PGROUP_POLICY_OBJECTW list{};
    const auto result = GetAppliedGPOListW(GPO_LIST_FLAG_MACHINE, nullptr, nullptr, &extension_guid, &list);
    struct cleanup { PGROUP_POLICY_OBJECTW value; ~cleanup() { if (value) FreeGPOListW(value); } } release{list};
    if (result != ERROR_SUCCESS) throw read_error{"unavailable"};
    group_policy_history history{extension, {}};
    std::set<PGROUP_POLICY_OBJECTW> visited;
    for (auto* row = list; row; row = row->pNext) {
      if (!visited.insert(row).second || visited.size() > max_gpos) throw read_error{"incomplete"};
      if (row->GPOLink == GPLinkMachine) continue;
      history.gpos.push_back({bounded_string(row->szGPOName, 49), bounded_string(row->lpDSPath),
          row->dwVersion, (row->dwOptions & GPO_FLAG_DISABLE) != 0});
    }
    snapshot.history.push_back(std::move(history));
  }
  require_logging_enabled();
  return snapshot;
}
std::string collect_in_worker() {
  group_policy_snapshot initial_domain;
  read_domain(initial_domain);
  if (!initial_domain.domain_joined) return empty_json("not-domain-joined");
  require_logging_enabled();
  if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) throw read_error{"unavailable"};
  struct apartment { ~apartment() { CoUninitialize(); } } release;
  const auto secured = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
  if (FAILED(secured) && secured != RPC_E_TOO_LATE) throw read_error{"unavailable"};
  Microsoft::WRL::ComPtr<IWbemLocator> locator;
  Microsoft::WRL::ComPtr<IWbemServices> services;
  if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator))))
    throw read_error{"unavailable"};
  bstr name(L"ROOT\\RSOP\\Computer");
  if (FAILED(locator->ConnectServer(name.value, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
      nullptr, nullptr, &services)) || !services || FAILED(CoSetProxyBlanket(services.Get(), RPC_C_AUTHN_WINNT,
      RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE)))
    throw read_error{"unavailable"};
  const auto before = read_snapshot(services.Get());
  const auto after = read_snapshot(services.Get());
  group_policy_snapshot final_domain;
  read_domain(final_domain);
  require_logging_enabled();
  if (initial_domain != final_domain || before.domain_joined != final_domain.domain_joined ||
      before.domain_dns != final_domain.domain_dns || before.domain_guid != final_domain.domain_guid)
    return empty_json("incomplete");
  return evaluate_windows_group_policy(before, after, now_utc());
}
class startup_attributes {
 public:
  std::vector<std::uint8_t> storage;
  LPPROC_THREAD_ATTRIBUTE_LIST list{};
  bool initialize(HANDLE output, HANDLE null_device) {
    SIZE_T bytes{}; InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    if (!bytes) return false;
    storage.resize(bytes); list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(list, 1, 0, &bytes)) { list = nullptr; return false; }
    inherited = {output, null_device};
    return UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited.data(), sizeof(inherited), nullptr, nullptr) != FALSE;
  }
  ~startup_attributes() { if (list) DeleteProcThreadAttributeList(list); }
 private:
  std::array<HANDLE, 2> inherited{};
};
}  // namespace

namespace ipms::agent::windows {
std::string group_policy_wmi_time_to_utc(std::string_view timestamp) {
  try {
    const auto parsed = wmi_ticks(timestamp);
    if (!parsed) return {};
    ULARGE_INTEGER adjusted{}; adjusted.QuadPart = *parsed;
    FILETIME file{adjusted.LowPart, adjusted.HighPart}; SYSTEMTIME time{};
    return FileTimeToSystemTime(&file, &time) ? utc_string(time) : std::string();
  } catch (...) { return {}; }
}

std::string evaluate_windows_group_policy(group_policy_snapshot before,
    group_policy_snapshot after, std::string_view observed_at) {
  try {
    const auto observed = utc_ticks(observed_at);
    if (!observed) return empty_json("incomplete");
    normalize_snapshot(before); normalize_snapshot(after);
    if (before != after) return empty_json("incomplete", observed_at);
    if (!before.domain_joined) return empty_json("not-domain-joined", observed_at);
    if (before.extensions.empty()) return empty_json("incomplete", observed_at);
    std::map<std::string, const group_policy_extension*> extensions;
    std::map<std::string, const group_policy_history*> history;
    for (const auto& extension : before.extensions) {
      const auto began = wmi_ticks(extension.begin_time);
      const auto ended = wmi_ticks(extension.end_time);
      // Dirty, running or future-dated RSoP data cannot confirm any GPO.
      // observed_at is rounded down to a whole UTC second on the same Agent
      // clock. Only that discarded fraction is allowed, never a future second.
      if (!began || !ended || *began > *ended || *ended >= *observed + 10000000ULL ||
          extension.logging_status == 2 || extension.logging_status < 1 || extension.logging_status > 3 ||
          (extension.guid == zero_guid && (extension.logging_status != 1 || extension.error != 0)))
        return empty_json("incomplete", observed_at);
      extensions.emplace(extension.guid, &extension);
    }
    for (const auto& item : before.history) history.emplace(item.extension_guid, &item);
    json::array records;
    for (const auto& gpo : before.gpos) {
      std::string status = "applied", processed;
      if (!gpo.enabled || gpo.access_denied || !gpo.filter_allowed) status = "excluded";
      else if (gpo.extension_ids.empty() || !directory_matches(gpo.directory_path, gpo.guid, before.domain_dns)) status = "unknown";
      else {
        bool unknown = false, failed = false;
        for (const auto& id : gpo.extension_ids) {
          const auto found = extensions.find(id);
          const auto applied = history.find(id);
          if (found == extensions.end() || applied == history.end()) { unknown = true; continue; }
          const auto& extension = *found->second;
          if (extension.error != 0) failed = true;
          if (extension.logging_status != 1) unknown = true;
          const auto& rows = applied->second->gpos;
          const auto matching = std::find_if(rows.begin(), rows.end(), [&](const auto& row) { return row.guid == gpo.guid; });
          if (matching == rows.end() || matching->disabled || matching->version != gpo.version ||
              !directory_matches(matching->directory_path, gpo.guid, before.domain_dns)) unknown = true;
          const auto ended = group_policy_wmi_time_to_utc(extension.end_time);
          if (processed.empty() || ended < processed) processed = ended;
        }
        if (failed) status = "failed";
        else if (unknown) status = "unknown";
      }
      records.emplace_back(json::object{{"guid", gpo.guid}, {"version", gpo.version}, {"status", status},
          {"processed_at", status == "applied" ? json::value(processed) : json::value(nullptr)}});
    }
    auto document = empty_evidence("collected", observed_at);
    document["domain_dns"] = before.domain_dns; document["domain_guid"] = before.domain_guid;
    document["gpos"] = std::move(records);
    return json::serialize(document, output_limits);
  } catch (...) { return empty_json("incomplete", utc_ticks(observed_at) ? observed_at : std::string_view()); }
}

std::string normalize_windows_group_policy_json(std::string_view document) {
  try {
    auto root = json::parse(document, output_limits).as<json::object>();
    if (root.size() != 8 || root.at("schema_version").as<std::string>() != "1" ||
        root.at("source").as<std::string>() != "windows-rsop-computer" || root.at("scope").as<std::string>() != "computer")
      return empty_json();
    const auto observed = utc_ticks(root.at("observed_at").as<std::string>());
    const auto now = utc_ticks(now_utc());
    if (!observed || !now || *observed > *now + 300ULL * 10000000ULL) return empty_json();
    const auto& status = root.at("status").as<std::string>();
    const auto& records = root.at("gpos").as<json::array>();
    if (status != "collected") {
      if ((status != "unavailable" && status != "incomplete" && status != "not-domain-joined") || !records.empty() ||
          !root.at("domain_dns").get_if<std::nullptr_t>() || !root.at("domain_guid").get_if<std::nullptr_t>()) return empty_json();
      return json::serialize(root, output_limits);
    }
    const auto& dns = root.at("domain_dns").as<std::string>();
    const auto& domain = root.at("domain_guid").as<std::string>();
    if (dns_name(dns) != dns || dns.empty() || uuid(domain) != domain || domain.empty() || records.size() > max_gpos) return empty_json();
    std::set<std::string> identities;
    for (const auto& record : records) {
      const auto& fields = record.as<json::object>();
      const auto& id = fields.at("guid").as<std::string>();
      const auto& processing = fields.at("status").as<std::string>();
      const auto version = fields.at("version").as<std::int64_t>();
      if (fields.size() != 4 || uuid(id) != id || id.empty() || !identities.insert(id).second || version < 0 || version > 0xFFFFFFFFLL)
        return empty_json();
      if (processing == "applied") {
        const auto processed = utc_ticks(fields.at("processed_at").as<std::string>());
        if (!processed || *processed > *observed) return empty_json();
      } else if ((processing != "excluded" && processing != "failed" && processing != "unknown") ||
                 !fields.at("processed_at").get_if<std::nullptr_t>()) return empty_json();
    }
    return json::serialize(root, output_limits);
  } catch (...) { return empty_json(); }
}

std::string bind_windows_group_policy_domain(std::string_view document, std::string_view expected_domain) {
  try {
    const auto supplied = json::parse(document, output_limits).as<json::object>();
    const auto normalized = normalize_windows_group_policy_json(document);
    const auto report = json::parse(normalized, output_limits).as<json::object>();
    // The normalizer deliberately substitutes unavailable for malformed input;
    // a binding failure is distinguished here without retaining its GPO rows.
    if (supplied != report) return empty_json("incomplete");
    if (report.at("status").as<std::string>() != "collected") return normalized;
    const auto domain = dns_name(std::string(expected_domain));
    if (domain.empty() || report.at("domain_dns").as<std::string>() != domain)
      return empty_json("incomplete", report.at("observed_at").as<std::string>());
    return normalized;
  } catch (...) { return empty_json("incomplete"); }
}

int run_windows_group_policy_worker() {
  std::string output;
  try { output = collect_in_worker(); }
  catch (const read_error& error) { output = empty_json(error.status); }
  catch (...) { output = empty_json(); }
  DWORD written{};
  const auto destination = GetStdHandle(STD_OUTPUT_HANDLE);
  return destination && destination != INVALID_HANDLE_VALUE && WriteFile(destination, output.data(),
      static_cast<DWORD>(output.size()), &written, nullptr) && written == output.size() ? 0 : 1;
}

std::string collect_windows_group_policy_json(const std::function<bool()>& cancelled, std::chrono::milliseconds timeout) {
  try {
    if ((cancelled && cancelled()) || timeout.count() <= 0 || timeout > std::chrono::seconds(30)) return empty_json();
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<wchar_t> executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!length || length >= executable.size()) return empty_json();
    const std::wstring path(executable.data(), length);
    if (path.find(L'"') != std::wstring::npos) return empty_json();
    std::wstring command = L"\"" + path + L"\"" + worker_argument;
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    handle reader, writer;
    if (!CreatePipe(&reader.value, &writer.value, &security, 16384) || !SetHandleInformation(reader.value, HANDLE_FLAG_INHERIT, 0)) return empty_json();
    handle null_device(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    handle job(CreateJobObjectW(nullptr, nullptr));
    if (!null_device || !job) return empty_json();
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1; limits.ProcessMemoryLimit = 128 * 1024 * 1024;
    if (!SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return empty_json();
    startup_attributes inherited;
    if (!inherited.initialize(writer.value, null_device.value)) return empty_json();
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_device.value; startup.StartupInfo.hStdError = null_device.value;
    startup.StartupInfo.hStdOutput = writer.value; startup.lpAttributeList = inherited.list;
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &child)) return empty_json();
    handle process(child.hProcess), thread(child.hThread);
    if (!AssignProcessToJobObject(job.value, process.value)) { TerminateProcess(process.value, 1); return empty_json(); }
    if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) return empty_json();
    writer.close();
    std::string output;
    for (;;) {
      if ((cancelled && cancelled()) || std::chrono::steady_clock::now() >= deadline) return empty_json();
      DWORD available{};
      const auto peeked = PeekNamedPipe(reader.value, nullptr, 0, nullptr, &available, nullptr);
      if (!peeked && GetLastError() != ERROR_BROKEN_PIPE) return empty_json();
      if (available) {
        if (output.size() + available > max_bytes) return empty_json("incomplete");
        std::array<char, 4096> buffer{}; DWORD bytes{};
        if (!ReadFile(reader.value, buffer.data(), (std::min)(available, static_cast<DWORD>(buffer.size())), &bytes, nullptr) || !bytes)
          return empty_json();
        output.append(buffer.data(), bytes);
      } else {
        const auto wait = WaitForSingleObject(process.value, 0);
        if (wait == WAIT_OBJECT_0) {
          DWORD final_bytes{};
          if (!PeekNamedPipe(reader.value, nullptr, 0, nullptr, &final_bytes, nullptr) && GetLastError() != ERROR_BROKEN_PIPE) return empty_json();
          if (final_bytes) continue;
          DWORD exit_code{};
          if (!GetExitCodeProcess(process.value, &exit_code) || exit_code != 0) return empty_json();
          return normalize_windows_group_policy_json(output);
        }
        if (wait != WAIT_TIMEOUT) return empty_json();
      }
      WaitForSingleObject(process.value, 10);
    }
  } catch (...) { return empty_json(); }
}
}  // namespace ipms::agent::windows
