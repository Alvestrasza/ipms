// File Name: windows_update_evidence.cpp
// Version: v0.1.0
// Created: 2026-09-13
// Last Modified: 2026-09-13
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Isolated offline WUA evidence collection with strict process/output limits.
#include "ipms/agent/windows_update_evidence.hpp"
#include "ipms/agent/management_json.hpp"

#include <windows.h>
#include <wuapi.h>
#include <oleauto.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {
namespace json = ipms::agent::management_json;
constexpr std::size_t k_max_updates = 128;
constexpr std::size_t k_max_evidence_bytes = 12 * 1024;
constexpr json::limits k_json_limits{k_max_evidence_bytes, 4, 1600, 128};
constexpr wchar_t k_worker_argument[] = L" --collect-windows-update-evidence";
constexpr wchar_t k_installed_software_query[] = L"IsInstalled=1 and Type='Software'";

class handle {
 public:
  HANDLE value{nullptr};
  handle() = default;
  explicit handle(HANDLE raw) : value(raw) {}
  handle(const handle&) = delete;
  handle& operator=(const handle&) = delete;
  ~handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
  explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
};

template <typename T> struct com_pointer {
  T* value{nullptr};
  ~com_pointer() { if (value) value->Release(); }
  T* operator->() const { return value; }
};

struct bstr {
  BSTR value{nullptr};
  explicit bstr(const wchar_t* text) : value(SysAllocString(text)) {}
  bstr() = default;
  ~bstr() { SysFreeString(value); }
};

std::string empty_evidence(std::string_view status = "unavailable") {
  return json::serialize(json::object{{"source", "wua-local-cache"}, {"status", status},
      {"observed_at", nullptr}, {"updates", json::array{}}}, k_json_limits);
}

std::string uuid(std::string value) {
  if (value.size() != 36) return {};
  bool nonzero = false;
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (value[i] != '-') return {};
    } else {
      const auto c = value[i];
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return {};
      if (c != '0') nonzero = true;
      if (c >= 'A' && c <= 'F') value[i] = static_cast<char>(c + ('a' - 'A'));
    }
  }
  return nonzero ? value : std::string();
}

bool utc_timestamp(const std::string& value) {
  if (value.size() != 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
      value[13] != ':' || value[16] != ':' || value[19] != 'Z') return false;
  auto number = [&](std::size_t offset, std::size_t length) -> WORD {
    WORD result = 0;
    for (std::size_t index = offset; index < offset + length; ++index) {
      if (value[index] < '0' || value[index] > '9') throw std::invalid_argument("timestamp");
      result = static_cast<WORD>(result * 10 + value[index] - '0');
    }
    return result;
  };
  SYSTEMTIME time{};
  time.wYear = number(0, 4); time.wMonth = number(5, 2); time.wDay = number(8, 2);
  time.wHour = number(11, 2); time.wMinute = number(14, 2); time.wSecond = number(17, 2);
  FILETIME filetime{};
  SYSTEMTIME roundtrip{};
  return SystemTimeToFileTime(&time, &filetime) && FileTimeToSystemTime(&filetime, &roundtrip) &&
      time.wYear == roundtrip.wYear && time.wMonth == roundtrip.wMonth && time.wDay == roundtrip.wDay &&
      time.wHour == roundtrip.wHour && time.wMinute == roundtrip.wMinute && time.wSecond == roundtrip.wSecond;
}

std::string now_utc() {
  SYSTEMTIME time{};
  GetSystemTime(&time);
  char value[21]{};
  const int length = std::snprintf(value, sizeof(value), "%04u-%02u-%02uT%02u:%02u:%02uZ",
      static_cast<unsigned>(time.wYear), static_cast<unsigned>(time.wMonth),
      static_cast<unsigned>(time.wDay), static_cast<unsigned>(time.wHour),
      static_cast<unsigned>(time.wMinute), static_cast<unsigned>(time.wSecond));
  return length == 20 ? std::string(value, 20) : std::string();
}

std::string collect_cache_in_worker() {
  // Search is synchronous only inside the disposable process. The parent owns
  // a hard wall-clock deadline including COM activation, search, and cleanup.
  const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(initialized)) return empty_evidence();
  struct apartment { ~apartment() { CoUninitialize(); } } cleanup;
  com_pointer<IUpdateSearcher> searcher;
  if (FAILED(CoCreateInstance(CLSID_UpdateSearcher, nullptr, CLSCTX_INPROC_SERVER,
      IID_IUpdateSearcher, reinterpret_cast<void**>(&searcher.value))) || !searcher.value) return empty_evidence();
  // These are per-search options. Do not set ServerSelection or ServiceID, and
  // do not register an update service or modify machine/group policy.
  if (FAILED(searcher->put_Online(VARIANT_FALSE)) ||
      FAILED(searcher->put_CanAutomaticallyUpgradeService(VARIANT_FALSE))) return empty_evidence();
  VARIANT_BOOL online = VARIANT_TRUE;
  if (FAILED(searcher->get_Online(&online)) || online != VARIANT_FALSE) return empty_evidence();
  bstr query(k_installed_software_query);
  if (!query.value) return empty_evidence();
  com_pointer<ISearchResult> result;
  if (FAILED(searcher->Search(query.value, &result.value)) || !result.value) return empty_evidence();
  OperationResultCode result_code = orcNotStarted;
  if (FAILED(result->get_ResultCode(&result_code)) || result_code != orcSucceeded) return empty_evidence();
  com_pointer<IUpdateCollection> updates;
  LONG count = 0;
  if (FAILED(result->get_Updates(&updates.value)) || !updates.value || FAILED(updates->get_Count(&count)) || count < 0)
    return empty_evidence();
  if (count > static_cast<LONG>(k_max_updates)) return empty_evidence("limit-exceeded");
  json::array installed;
  for (LONG index = 0; index < count; ++index) {
    com_pointer<IUpdate> update;
    com_pointer<IUpdateIdentity> identity;
    VARIANT_BOOL is_installed = VARIANT_FALSE;
    UpdateType type = utDriver;
    bstr id;
    LONG revision = 0;
    if (FAILED(updates->get_Item(index, &update.value)) || !update.value ||
        FAILED(update->get_IsInstalled(&is_installed)) || is_installed != VARIANT_TRUE ||
        FAILED(update->get_Type(&type)) || type != utSoftware ||
        FAILED(update->get_Identity(&identity.value)) || !identity.value ||
        FAILED(identity->get_UpdateID(&id.value)) || !id.value || SysStringLen(id.value) != 36 ||
        FAILED(identity->get_RevisionNumber(&revision)) || revision < 1) return empty_evidence();
    std::string ascii_id;
    for (UINT offset = 0; offset < 36; ++offset) {
      if (id.value[offset] > 127) return empty_evidence();
      ascii_id.push_back(static_cast<char>(id.value[offset]));
    }
    ascii_id = uuid(std::move(ascii_id));
    if (ascii_id.empty()) return empty_evidence();
    installed.emplace_back(json::object{{"update_id", ascii_id}, {"revision", revision}});
  }
  return ipms::agent::windows::normalize_windows_update_evidence_json(json::serialize(
      json::object{{"source", "wua-local-cache"}, {"status", "collected"},
      {"observed_at", now_utc()}, {"updates", std::move(installed)}}, k_json_limits));
}

class startup_attributes {
 public:
  std::vector<unsigned char> storage;
  LPPROC_THREAD_ATTRIBUTE_LIST list{nullptr};
  bool initialize(HANDLE output, HANDLE null_device) {
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    if (bytes == 0) return false;
    storage.resize(bytes);
    list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
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
std::string normalize_windows_update_evidence_json(std::string_view document) {
  try {
    auto root = json::parse(document, k_json_limits).as<json::object>();
    if (root.size() != 4 || root.at("source").as<std::string>() != "wua-local-cache") return empty_evidence();
    const auto& status = root.at("status").as<std::string>();
    const auto& records = root.at("updates").as<json::array>();
    if (status == "unavailable" || status == "limit-exceeded") {
      if (!records.empty() || !root.at("observed_at").get_if<std::nullptr_t>()) return empty_evidence();
      return empty_evidence(status);
    }
    if (status != "collected" || !utc_timestamp(root.at("observed_at").as<std::string>())) return empty_evidence();
    if (records.size() > k_max_updates) return empty_evidence("limit-exceeded");
    std::map<std::pair<std::string, std::int64_t>, bool> identities;
    for (const auto& record : records) {
      const auto& fields = record.as<json::object>();
      if (fields.size() != 2) return empty_evidence();
      const auto id = uuid(fields.at("update_id").as<std::string>());
      const auto revision = fields.at("revision").as<std::int64_t>();
      if (id.empty() || revision < 1 || revision > (std::numeric_limits<std::int32_t>::max)()) return empty_evidence();
      identities.emplace(std::make_pair(id, revision), true);
    }
    json::array normalized;
    for (const auto& [key, _] : identities) normalized.emplace_back(json::object{{"update_id", key.first}, {"revision", key.second}});
    root["updates"] = std::move(normalized);
    return json::serialize(root, k_json_limits);
  } catch (...) { return empty_evidence(); }
}

int run_windows_update_evidence_worker() {
  std::string output;
  try { output = collect_cache_in_worker(); } catch (...) { output = empty_evidence(); }
  DWORD written = 0;
  const HANDLE destination = GetStdHandle(STD_OUTPUT_HANDLE);
  return destination && destination != INVALID_HANDLE_VALUE &&
      WriteFile(destination, output.data(), static_cast<DWORD>(output.size()), &written, nullptr) &&
      written == output.size() ? 0 : 1;
}

std::string collect_windows_update_evidence_json(std::chrono::milliseconds timeout) {
  try {
    if (timeout.count() <= 0 || timeout > std::chrono::seconds(15)) return empty_evidence();
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<wchar_t> executable(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!length || length >= executable.size()) return empty_evidence();
    const std::wstring path(executable.data(), length);
    if (path.find(L'"') != std::wstring::npos) return empty_evidence();
    std::wstring command = L"\"" + path + L"\"" + k_worker_argument;
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    handle reader, writer;
    if (!CreatePipe(&reader.value, &writer.value, &security, 16384) ||
        !SetHandleInformation(reader.value, HANDLE_FLAG_INHERIT, 0)) return empty_evidence();
    handle null_device(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    handle job(CreateJobObjectW(nullptr, nullptr));
    if (!null_device || !job) return empty_evidence();
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = 128 * 1024 * 1024;
    if (!SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return empty_evidence();
    startup_attributes attributes;
    if (!attributes.initialize(writer.value, null_device.value)) return empty_evidence();
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_device.value;
    startup.StartupInfo.hStdError = null_device.value;
    startup.StartupInfo.hStdOutput = writer.value;
    startup.lpAttributeList = attributes.list;
    PROCESS_INFORMATION process_info{};
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        nullptr, nullptr, &startup.StartupInfo, &process_info)) return empty_evidence();
    handle process(process_info.hProcess), thread(process_info.hThread);
    // Never run the child unless the kill-on-close boundary is established.
    if (!AssignProcessToJobObject(job.value, process.value)) {
      TerminateProcess(process.value, 1);
      return empty_evidence();
    }
    if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) return empty_evidence();
    CloseHandle(writer.value); writer.value = nullptr;
    std::string output;
    for (;;) {
      if (std::chrono::steady_clock::now() >= deadline) return empty_evidence();
      DWORD available = 0;
      const BOOL peeked = PeekNamedPipe(reader.value, nullptr, 0, nullptr, &available, nullptr);
      if (!peeked && GetLastError() != ERROR_BROKEN_PIPE) return empty_evidence();
      if (available) {
        if (output.size() + available > k_max_evidence_bytes) return empty_evidence();
        std::array<char, 4096> buffer{};
        DWORD bytes = 0;
        if (!ReadFile(reader.value, buffer.data(), std::min<DWORD>(available, static_cast<DWORD>(buffer.size())), &bytes, nullptr) || !bytes)
          return empty_evidence();
        output.append(buffer.data(), bytes);
      } else {
        const DWORD wait = WaitForSingleObject(process.value, 0);
        if (wait == WAIT_OBJECT_0) {
          // The child can write its final bytes between the earlier peek and
          // the process wait. Drain those bytes before accepting the exit.
          DWORD final_bytes = 0;
          const BOOL final_peek = PeekNamedPipe(reader.value, nullptr, 0, nullptr, &final_bytes, nullptr);
          if (!final_peek && GetLastError() != ERROR_BROKEN_PIPE) return empty_evidence();
          if (final_bytes) continue;
          DWORD exit_code = 1;
          if (!GetExitCodeProcess(process.value, &exit_code) || exit_code != 0) return empty_evidence();
          return normalize_windows_update_evidence_json(output);
        }
        if (wait != WAIT_TIMEOUT) return empty_evidence();
      }
      if (std::chrono::steady_clock::now() >= deadline) return empty_evidence();
      // All COM calls and their destructors live behind this bounded process.
      WaitForSingleObject(process.value, 10);
    }
  } catch (...) { return empty_evidence(); }
}
}  // namespace ipms::agent::windows
