#include "ipms/agent/windows_telemetry.hpp"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <sstream>
#include <string>

namespace {
std::string utf8(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(
      CP_UTF8,
      WC_ERR_INVALID_CHARS,
      value.data(),
      static_cast<int>(value.size()),
      nullptr,
      0,
      nullptr,
      nullptr);
  if (size <= 0) return {};
  std::string result(size, '\0');
  if (!WideCharToMultiByte(
          CP_UTF8,
          WC_ERR_INVALID_CHARS,
          value.data(),
          static_cast<int>(value.size()),
          result.data(),
          size,
          nullptr,
          nullptr)) {
    return {};
  }
  return result;
}

std::string json_escape(const std::string& value) {
  std::ostringstream escaped;
  for (const unsigned char character : value) {
    switch (character) {
      case '"': escaped << "\\\""; break;
      case '\\': escaped << "\\\\"; break;
      case '\b': escaped << "\\b"; break;
      case '\f': escaped << "\\f"; break;
      case '\n': escaped << "\\n"; break;
      case '\r': escaped << "\\r"; break;
      case '\t': escaped << "\\t"; break;
      default: if (character < 0x20) escaped << '?'; else escaped << static_cast<char>(character);
    }
  }
  return escaped.str();
}

std::uint64_t file_time(const FILETIME& value) {
  ULARGE_INTEGER integer{};
  integer.LowPart = value.dwLowDateTime;
  integer.HighPart = value.dwHighDateTime;
  return integer.QuadPart;
}

unsigned cpu_utilization_percent() {
  FILETIME idle_before{}, kernel_before{}, user_before{};
  FILETIME idle_after{}, kernel_after{}, user_after{};
  if (!GetSystemTimes(&idle_before, &kernel_before, &user_before)) return 0;
  Sleep(250);
  if (!GetSystemTimes(&idle_after, &kernel_after, &user_after)) return 0;
  const auto idle = file_time(idle_after) - file_time(idle_before);
  const auto kernel = file_time(kernel_after) - file_time(kernel_before);
  const auto user = file_time(user_after) - file_time(user_before);
  const auto total = kernel + user;
  if (total == 0 || idle > total) return 0;
  return static_cast<unsigned>(std::min<std::uint64_t>(100, ((total - idle) * 100 + total / 2) / total));
}

std::string fixed_volumes_json() {
  DWORD length = GetLogicalDriveStringsW(0, nullptr);
  if (length == 0 || length > 32 * 1024) return "[]";
  std::wstring drives(length + 1, L'\0');
  if (GetLogicalDriveStringsW(length, drives.data()) == 0) return "[]";

  std::ostringstream json;
  json << '[';
  std::size_t count = 0;
  for (const wchar_t* root = drives.c_str(); *root != L'\0' && count < 64; root += std::wcslen(root) + 1) {
    if (GetDriveTypeW(root) != DRIVE_FIXED) continue;
    ULARGE_INTEGER available{}, total{}, free{};
    if (!GetDiskFreeSpaceExW(root, &available, &total, &free) || total.QuadPart == 0) continue;
    wchar_t label[MAX_PATH + 1]{};
    wchar_t filesystem[MAX_PATH + 1]{};
    (void)GetVolumeInformationW(
        root,
        label,
        MAX_PATH,
        nullptr,
        nullptr,
        nullptr,
        filesystem,
        MAX_PATH);
    const auto used = total.QuadPart - free.QuadPart;
    const auto percent = static_cast<unsigned>((used * 100 + total.QuadPart / 2) / total.QuadPart);
    if (count++ != 0) json << ',';
    json << "{\"name\":\"" << json_escape(utf8(root))
         << "\",\"label\":\"" << json_escape(utf8(label))
         << "\",\"filesystem\":\"" << json_escape(utf8(filesystem))
         << "\",\"total_bytes\":" << total.QuadPart
         << ",\"free_bytes\":" << free.QuadPart
         << ",\"used_percent\":" << percent << '}';
  }
  json << ']';
  return json.str();
}
}  // namespace

namespace ipms::agent::windows {
std::string collect_windows_telemetry_json() {
  MEMORYSTATUSEX memory{sizeof(MEMORYSTATUSEX)};
  if (!GlobalMemoryStatusEx(&memory)) return {};
  const auto memory_used = memory.ullTotalPhys - memory.ullAvailPhys;
  std::ostringstream json;
  json << "{\"schema_version\":\"1\",\"pack\":\"windows-server-core\","
       << "\"cpu_used_percent\":" << cpu_utilization_percent() << ','
       << "\"memory_total_bytes\":" << memory.ullTotalPhys << ','
       << "\"memory_available_bytes\":" << memory.ullAvailPhys << ','
       << "\"memory_used_bytes\":" << memory_used << ','
       << "\"memory_used_percent\":" << static_cast<unsigned>(memory.dwMemoryLoad) << ','
       << "\"fixed_volumes\":" << fixed_volumes_json() << '}';
  return json.str();
}
}  // namespace ipms::agent::windows
