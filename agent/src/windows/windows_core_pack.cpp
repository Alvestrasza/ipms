#include "ipms/agent/gateway_contract.hpp"
#include "ipms/agent/windows_core_pack.hpp"

#include <windows.h>

#include <sstream>
#include <string>

namespace {
std::string utf8(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  std::string result(size, '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
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
      default: if (character < 0x20) escaped << "?"; else escaped << static_cast<char>(character);
    }
  }
  return escaped.str();
}

std::wstring computer_name() {
  DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
  std::wstring value(size, L'\0');
  if (!GetComputerNameW(value.data(), &size)) return L"unknown";
  value.resize(size);
  return value;
}

std::wstring registry_string(const wchar_t* name) {
  HKEY key{};
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &key) != ERROR_SUCCESS) return L"unknown";
  wchar_t buffer[512]{};
  DWORD size = sizeof(buffer);
  const auto status = RegQueryValueExW(key, name, nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &size);
  RegCloseKey(key);
  return status == ERROR_SUCCESS ? std::wstring(buffer) : L"unknown";
}
}  // namespace

namespace ipms::agent::windows {
std::string collect_windows_server_core_inventory_json() {
  SYSTEM_INFO system_info{};
  GetNativeSystemInfo(&system_info);
  MEMORYSTATUSEX memory{sizeof(MEMORYSTATUSEX)};
  GlobalMemoryStatusEx(&memory);
  std::ostringstream json;
  json << "{\"schema_version\":\"1\",\"pack\":\"windows-server-core\","
       << "\"agent_gateway_port\":" << ipms::agent::k_default_agent_gateway_port << ","
       << "\"hostname\":\"" << json_escape(utf8(computer_name())) << "\","
       << "\"os_product\":\"" << json_escape(utf8(registry_string(L"ProductName"))) << "\","
       << "\"os_build\":\"" << json_escape(utf8(registry_string(L"CurrentBuildNumber"))) << "\","
       << "\"architecture\":\"" << (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "other") << "\","
       << "\"logical_processors\":" << system_info.dwNumberOfProcessors << ","
       << "\"memory_total_bytes\":" << memory.ullTotalPhys << "}";
  return json.str();
}
}  // namespace ipms::agent::windows
