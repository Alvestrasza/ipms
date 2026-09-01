#include "ipms/agent/gateway_contract.hpp"
#include "ipms/agent/windows_core_pack.hpp"

#include <windows.h>
#include <wbemidl.h>
#include <wrl/client.h>

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <string>
#include <string_view>

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

struct com_scope {
  bool initialized{false};
  com_scope() {
    const HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    initialized = SUCCEEDED(result);
  }
  ~com_scope() { if (initialized) CoUninitialize(); }
};

std::wstring wmi_string(IWbemClassObject* object, const wchar_t* property) {
  VARIANT value{};
  VariantInit(&value);
  const HRESULT result = object->Get(property, 0, &value, nullptr, nullptr);
  std::wstring text;
  if (SUCCEEDED(result) && value.vt == VT_BSTR && value.bstrVal != nullptr) {
    text.assign(value.bstrVal, SysStringLen(value.bstrVal));
  }
  VariantClear(&value);
  return text;
}

Microsoft::WRL::ComPtr<IWbemClassObject> query_first(
    IWbemServices* services,
    const wchar_t* query) {
  BSTR language = SysAllocString(L"WQL");
  BSTR statement = SysAllocString(query);
  if (language == nullptr || statement == nullptr) {
    if (language != nullptr) SysFreeString(language);
    if (statement != nullptr) SysFreeString(statement);
    return {};
  }
  Microsoft::WRL::ComPtr<IEnumWbemClassObject> rows;
  const HRESULT query_result = services->ExecQuery(
      language,
      statement,
      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
      nullptr,
      &rows);
  SysFreeString(language);
  SysFreeString(statement);
  if (FAILED(query_result) || !rows) return {};
  Microsoft::WRL::ComPtr<IWbemClassObject> row;
  ULONG returned = 0;
  if (FAILED(rows->Next(5'000, 1, row.ReleaseAndGetAddressOf(), &returned)) || returned != 1) {
    return {};
  }
  return row;
}

struct windows_identity {
  std::wstring os_name;
  std::wstring manufacturer;
  std::wstring model;
};

windows_identity read_windows_identity() {
  com_scope com;
  if (!com.initialized) return {};
  const HRESULT security = CoInitializeSecurity(
      nullptr,
      -1,
      nullptr,
      nullptr,
      RPC_C_AUTHN_LEVEL_DEFAULT,
      RPC_C_IMP_LEVEL_IMPERSONATE,
      nullptr,
      EOAC_NONE,
      nullptr);
  if (FAILED(security) && security != RPC_E_TOO_LATE) return {};

  Microsoft::WRL::ComPtr<IWbemLocator> locator;
  if (FAILED(CoCreateInstance(
          CLSID_WbemLocator,
          nullptr,
          CLSCTX_INPROC_SERVER,
          IID_PPV_ARGS(&locator)))) {
    return {};
  }
  BSTR namespace_path = SysAllocString(L"ROOT\\CIMV2");
  if (namespace_path == nullptr) return {};
  Microsoft::WRL::ComPtr<IWbemServices> services;
  const HRESULT connection = locator->ConnectServer(
      namespace_path,
      nullptr,
      nullptr,
      nullptr,
      0,
      nullptr,
      nullptr,
      &services);
  SysFreeString(namespace_path);
  if (FAILED(connection) || !services) return {};
  if (FAILED(CoSetProxyBlanket(
          services.Get(),
          RPC_C_AUTHN_WINNT,
          RPC_C_AUTHZ_NONE,
          nullptr,
          RPC_C_AUTHN_LEVEL_CALL,
          RPC_C_IMP_LEVEL_IMPERSONATE,
          nullptr,
          EOAC_NONE))) {
    return {};
  }

  windows_identity identity;
  if (auto operating_system = query_first(
          services.Get(),
          L"SELECT Caption FROM Win32_OperatingSystem")) {
    identity.os_name = wmi_string(operating_system.Get(), L"Caption");
  }
  if (auto computer_system = query_first(
          services.Get(),
          L"SELECT Manufacturer, Model FROM Win32_ComputerSystem")) {
    identity.manufacturer = wmi_string(computer_system.Get(), L"Manufacturer");
    identity.model = wmi_string(computer_system.Get(), L"Model");
  }
  return identity;
}

bool contains_case_insensitive(std::wstring value, std::wstring_view needle) {
  std::transform(value.begin(), value.end(), value.begin(), [](wchar_t character) {
    return static_cast<wchar_t>(std::towlower(character));
  });
  return value.find(needle) != std::wstring::npos;
}

std::string machine_type(const windows_identity& identity) {
  if (identity.model.empty()) return "unknown";
  const std::wstring combined = identity.manufacturer + L" " + identity.model;
  constexpr std::wstring_view virtual_markers[] = {
      L"virtual machine",
      L"vmware",
      L"virtualbox",
      L"kvm",
      L"qemu",
      L"xen",
      L"hvm domu",
      L"parallels",
      L"bhyve",
      L"bochs",
      L"rhev hypervisor",
      L"google compute engine",
      L"amazon ec2",
  };
  for (const auto marker : virtual_markers) {
    if (contains_case_insensitive(combined, marker)) return "virtual";
  }
  return "physical";
}
}  // namespace

namespace ipms::agent::windows {
std::string collect_windows_server_core_inventory_json() {
  SYSTEM_INFO system_info{};
  GetNativeSystemInfo(&system_info);
  MEMORYSTATUSEX memory{sizeof(MEMORYSTATUSEX)};
  GlobalMemoryStatusEx(&memory);
  const auto identity = read_windows_identity();
  const auto product_name = registry_string(L"ProductName");
  const auto operating_system = identity.os_name.empty() ? product_name : identity.os_name;
  std::ostringstream json;
  json << "{\"schema_version\":\"1\",\"pack\":\"windows-server-core\","
       << "\"agent_gateway_port\":" << ipms::agent::k_default_agent_gateway_port << ","
       << "\"hostname\":\"" << json_escape(utf8(computer_name())) << "\","
       << "\"os_product\":\"" << json_escape(utf8(product_name)) << "\","
       << "\"os_name\":\"" << json_escape(utf8(operating_system)) << "\","
       << "\"os_build\":\"" << json_escape(utf8(registry_string(L"CurrentBuildNumber"))) << "\","
       << "\"architecture\":\"" << (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "other") << "\","
       << "\"manufacturer\":\"" << json_escape(utf8(identity.manufacturer)) << "\","
       << "\"model\":\"" << json_escape(utf8(identity.model)) << "\","
       << "\"machine_type\":\"" << machine_type(identity) << "\","
       << "\"logical_processors\":" << system_info.dwNumberOfProcessors << ","
       << "\"memory_total_bytes\":" << memory.ullTotalPhys << "}";
  return json.str();
}
}  // namespace ipms::agent::windows
