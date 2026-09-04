#include "ipms/agent/windows_software_pack.hpp"

#include <windows.h>
#include <objbase.h>

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {
constexpr std::size_t k_max_packages = 2'048;
constexpr std::size_t k_max_page_items = 128;
constexpr std::size_t k_max_page_item_bytes = 48 * 1024;

std::string utf8(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                       static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (size <= 0) return {};
  std::string result(static_cast<std::size_t>(size), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) != size) {
    return {};
  }
  return result;
}

std::string json_escape(std::string_view value) {
  std::ostringstream output;
  for (const unsigned char character : value) {
    switch (character) {
      case '"': output << "\\\""; break;
      case '\\': output << "\\\\"; break;
      case '\b': output << "\\b"; break;
      case '\f': output << "\\f"; break;
      case '\n': output << "\\n"; break;
      case '\r': output << "\\r"; break;
      case '\t': output << "\\t"; break;
      default:
        if (character < 0x20) {
          output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                 << static_cast<unsigned>(character) << std::dec;
        } else {
          output << static_cast<char>(character);
        }
    }
  }
  return output.str();
}

std::wstring registry_string(HKEY key, const wchar_t* name) {
  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
      (type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(wchar_t) || bytes > 16'384) {
    return {};
  }
  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, name, nullptr, &type,
                       reinterpret_cast<BYTE*>(value.data()), &bytes) != ERROR_SUCCESS) {
    return {};
  }
  while (!value.empty() && value.back() == L'\0') value.pop_back();
  if (value.size() > 255) value.resize(255);
  return value;
}

DWORD registry_dword(HKEY key, const wchar_t* name) {
  DWORD value = 0;
  DWORD type = 0;
  DWORD bytes = sizeof(value);
  return RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &bytes) == ERROR_SUCCESS &&
                 type == REG_DWORD && bytes == sizeof(value)
             ? value
             : 0;
}

std::string stable_id(std::wstring_view view, std::wstring_view key_name) {
  std::uint64_t hash = 1469598103934665603ULL;
  for (const wchar_t character : view) {
    hash ^= static_cast<std::uint64_t>(character);
    hash *= 1099511628211ULL;
  }
  for (const wchar_t character : key_name) {
    hash ^= static_cast<std::uint64_t>(character);
    hash *= 1099511628211ULL;
  }
  std::ostringstream value;
  value << "windows:" << std::hex << std::setw(16) << std::setfill('0') << hash;
  return value.str();
}

struct package_record {
  std::string source_id;
  std::string name;
  std::string version;
  std::string publisher;
  bool os_component{false};
};

void collect_uninstall_view(REGSAM view_flag, std::wstring_view view_name,
                            std::map<std::string, package_record>& records) {
  HKEY uninstall = nullptr;
  constexpr wchar_t path[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | view_flag, &uninstall) != ERROR_SUCCESS) return;
  for (DWORD index = 0; index < k_max_packages; ++index) {
    wchar_t key_name[256]{};
    DWORD key_name_size = static_cast<DWORD>(std::size(key_name));
    const auto status = RegEnumKeyExW(uninstall, index, key_name, &key_name_size,
                                      nullptr, nullptr, nullptr, nullptr);
    if (status == ERROR_NO_MORE_ITEMS) break;
    if (status != ERROR_SUCCESS) continue;
    HKEY package_key = nullptr;
    if (RegOpenKeyExW(uninstall, key_name, 0, KEY_READ | view_flag, &package_key) != ERROR_SUCCESS) continue;
    const auto display_name = registry_string(package_key, L"DisplayName");
    if (!display_name.empty()) {
      const auto release_type = registry_string(package_key, L"ReleaseType");
      const bool os_component = registry_dword(package_key, L"SystemComponent") == 1 ||
                                !release_type.empty() ||
                                registry_dword(package_key, L"WindowsInstaller") == 0 &&
                                    display_name.rfind(L"Update for ", 0) == 0;
      const auto id = stable_id(view_name, std::wstring_view(key_name, key_name_size));
      records.emplace(id, package_record{
                              id,
                              utf8(display_name),
                              utf8(registry_string(package_key, L"DisplayVersion")),
                              utf8(registry_string(package_key, L"Publisher")),
                              os_component,
                          });
    }
    RegCloseKey(package_key);
    if (records.size() >= k_max_packages) break;
  }
  RegCloseKey(uninstall);
}

bool reboot_required() {
  HKEY key = nullptr;
  constexpr wchar_t path[] =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired";
  const bool exists = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS;
  if (key) RegCloseKey(key);
  return exists;
}

std::string windows_update_time(const wchar_t* result_type) {
  const std::wstring path =
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\" +
      std::wstring(result_type);
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                    KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
    return {};
  }
  const auto value = utf8(registry_string(key, L"LastSuccessTime"));
  RegCloseKey(key);
  return value;
}

std::string snapshot_id() {
  GUID guid{};
  if (CoCreateGuid(&guid) != S_OK) return {};
  wchar_t text[39]{};
  if (StringFromGUID2(guid, text, static_cast<int>(std::size(text))) == 0) return {};
  std::wstring value(text);
  if (value.size() == 38 && value.front() == L'{' && value.back() == L'}') {
    value = value.substr(1, 36);
  }
  std::transform(value.begin(), value.end(), value.begin(),
                 [](wchar_t character) { return static_cast<wchar_t>(std::towlower(character)); });
  return utf8(value);
}

std::string package_json(const package_record& package) {
  std::ostringstream json;
  json << "{\"source_id\":\"" << json_escape(package.source_id)
       << "\",\"name\":\"" << json_escape(package.name)
       << "\",\"installed_version\":\"" << json_escape(package.version)
       << "\",\"available_version\":\"\",\"publisher\":\""
       << json_escape(package.publisher)
       << "\",\"package_type\":\"windows-package\",\"update_state\":\"unknown\","
       << "\"is_os_component\":" << (package.os_component ? "true" : "false") << "}";
  return json.str();
}
}  // namespace

namespace ipms::agent::windows {

std::vector<std::string> collect_windows_software_inventory_pages() {
  std::map<std::string, package_record> records;
  collect_uninstall_view(KEY_WOW64_64KEY, L"64", records);
  collect_uninstall_view(KEY_WOW64_32KEY, L"32", records);
  std::vector<std::vector<std::string>> pages(1);
  std::size_t page_bytes = 0;
  for (const auto& [_, record] : records) {
    const auto item = package_json(record);
    if (!pages.back().empty() &&
        (pages.back().size() >= k_max_page_items || page_bytes + item.size() > k_max_page_item_bytes)) {
      if (pages.size() >= 64) break;
      pages.emplace_back();
      page_bytes = 0;
    }
    pages.back().push_back(item);
    page_bytes += item.size() + 1;
  }
  const auto id = snapshot_id();
  if (id.empty()) return {};
  const auto last_scan = windows_update_time(L"Detect");
  const auto last_install = windows_update_time(L"Install");
  std::vector<std::string> result;
  result.reserve(pages.size());
  for (std::size_t page_index = 0; page_index < pages.size(); ++page_index) {
    std::ostringstream json;
    json << "{\"schema_version\":\"1\",\"platform\":\"windows\","
         << "\"snapshot_id\":\"" << id << "\",\"page_index\":" << page_index
         << ",\"page_count\":" << pages.size() << ",\"reboot_required\":"
         << (reboot_required() ? "true" : "false")
         << ",\"update_scan_status\":\"unknown\",\"last_update_scan_at\":"
         << (last_scan.empty() ? "null" : "\"" + json_escape(last_scan) + "\"")
         << ",\"last_update_install_at\":"
         << (last_install.empty() ? "null" : "\"" + json_escape(last_install) + "\"")
         << ",\"packages\":[";
    for (std::size_t item_index = 0; item_index < pages[page_index].size(); ++item_index) {
      if (item_index) json << ',';
      json << pages[page_index][item_index];
    }
    json << "]}";
    result.push_back(json.str());
  }
  return result;
}

}  // namespace ipms::agent::windows
