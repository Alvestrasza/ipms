#include "ipms/agent/gateway_contract.hpp"
#include "ipms/agent/windows_core_pack.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <wrl/client.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

std::wstring computer_name_ex(COMPUTER_NAME_FORMAT format) {
  DWORD size = 0;
  GetComputerNameExW(format, nullptr, &size);
  if (size == 0 || GetLastError() != ERROR_MORE_DATA) return {};
  std::wstring value(size, L'\0');
  if (!GetComputerNameExW(format, value.data(), &size)) return {};
  value.resize(size);
  return value;
}

std::wstring native_os_version() {
  using rtl_get_version = LONG(WINAPI*)(OSVERSIONINFOW*);
  const auto module = GetModuleHandleW(L"ntdll.dll");
  if (module == nullptr) return {};
  const auto get_version = reinterpret_cast<rtl_get_version>(
      GetProcAddress(module, "RtlGetVersion"));
  if (get_version == nullptr) return {};
  OSVERSIONINFOW version{};
  version.dwOSVersionInfoSize = sizeof(version);
  if (get_version(&version) != 0) return {};
  return std::to_wstring(version.dwMajorVersion) + L"." +
         std::to_wstring(version.dwMinorVersion) + L"." +
         std::to_wstring(version.dwBuildNumber);
}

std::wstring registry_string_at(const wchar_t* path, const wchar_t* name) {
  HKEY key{};
  if (RegOpenKeyExW(
          HKEY_LOCAL_MACHINE,
          path,
          0,
          KEY_READ | KEY_WOW64_64KEY,
          &key) != ERROR_SUCCESS) {
    return {};
  }
  wchar_t buffer[512]{};
  DWORD size = sizeof(buffer);
  DWORD type = 0;
  const auto status = RegQueryValueExW(
      key,
      name,
      nullptr,
      &type,
      reinterpret_cast<LPBYTE>(buffer),
      &size);
  RegCloseKey(key);
  if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return {};
  std::size_t length = size / sizeof(wchar_t);
  while (length > 0 && buffer[length - 1] == L'\0') --length;
  return std::wstring(buffer, length);
}

std::wstring registry_string(const wchar_t* name) {
  return registry_string_at(
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      name);
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

bool wmi_bool(IWbemClassObject* object, const wchar_t* property) {
  VARIANT value{};
  VariantInit(&value);
  const HRESULT result = object->Get(property, 0, &value, nullptr, nullptr);
  const bool boolean = SUCCEEDED(result) && value.vt == VT_BOOL && value.boolVal == VARIANT_TRUE;
  VariantClear(&value);
  return boolean;
}

std::optional<std::uint32_t> wmi_uint32(
    IWbemClassObject* object,
    const wchar_t* property) {
  VARIANT value{};
  VariantInit(&value);
  const HRESULT result = object->Get(property, 0, &value, nullptr, nullptr);
  std::optional<std::uint32_t> number;
  if (SUCCEEDED(result)) {
    switch (value.vt) {
      case VT_UI1: number = value.bVal; break;
      case VT_I1: if (value.cVal >= 0) number = static_cast<std::uint32_t>(value.cVal); break;
      case VT_UI2: number = value.uiVal; break;
      case VT_I2: if (value.iVal >= 0) number = static_cast<std::uint32_t>(value.iVal); break;
      case VT_UI4: number = value.ulVal; break;
      case VT_I4: if (value.lVal >= 0) number = static_cast<std::uint32_t>(value.lVal); break;
      default: break;
    }
  }
  VariantClear(&value);
  return number;
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
  std::wstring os_version;
  std::wstring manufacturer;
  std::wstring model;
  std::wstring domain;
  bool part_of_domain{false};
};

windows_identity read_windows_identity() {
  windows_identity identity;
  identity.os_version = native_os_version();
  identity.domain = computer_name_ex(ComputerNameDnsDomain);
  identity.part_of_domain = !identity.domain.empty();
  com_scope com;
  if (!com.initialized) return identity;
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
  if (FAILED(security) && security != RPC_E_TOO_LATE) return identity;

  Microsoft::WRL::ComPtr<IWbemLocator> locator;
  if (FAILED(CoCreateInstance(
          CLSID_WbemLocator,
          nullptr,
          CLSCTX_INPROC_SERVER,
          IID_PPV_ARGS(&locator)))) {
    return identity;
  }
  BSTR namespace_path = SysAllocString(L"ROOT\\CIMV2");
  if (namespace_path == nullptr) return identity;
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
  if (FAILED(connection) || !services) return identity;
  if (FAILED(CoSetProxyBlanket(
          services.Get(),
          RPC_C_AUTHN_WINNT,
          RPC_C_AUTHZ_NONE,
          nullptr,
          RPC_C_AUTHN_LEVEL_CALL,
          RPC_C_IMP_LEVEL_IMPERSONATE,
          nullptr,
          EOAC_NONE))) {
    return identity;
  }

  if (auto operating_system = query_first(
          services.Get(),
          L"SELECT Caption, Version FROM Win32_OperatingSystem")) {
    identity.os_name = wmi_string(operating_system.Get(), L"Caption");
    const auto version = wmi_string(operating_system.Get(), L"Version");
    if (!version.empty()) identity.os_version = version;
  }
  if (auto computer_system = query_first(
          services.Get(),
          L"SELECT Manufacturer, Model, Domain, PartOfDomain FROM Win32_ComputerSystem")) {
    identity.manufacturer = wmi_string(computer_system.Get(), L"Manufacturer");
    identity.model = wmi_string(computer_system.Get(), L"Model");
    const auto part_of_domain =
        wmi_bool(computer_system.Get(), L"PartOfDomain");
    const auto domain = wmi_string(computer_system.Get(), L"Domain");
    if (part_of_domain && !domain.empty()) identity.domain = domain;
    identity.part_of_domain = part_of_domain || !identity.domain.empty();
  }
  return identity;
}

struct installed_server_feature {
  std::wstring unique_name;
  std::wstring display_name;
  std::wstring parent_name;
  std::string type;
};

struct legacy_server_feature {
  std::uint32_t id;
  std::uint32_t parent_id;
  std::wstring display_name;
};

bool is_legacy_server_role(std::uint32_t id) {
  switch (id) {
    case 1:
    case 2:
    case 3:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 21:
    case 404:
    case 409:
    case 468:
    case 481:
    case 485:
      return true;
    default:
      return false;
  }
}

std::wstring legacy_server_feature_name(std::uint32_t id) {
  return L"win32-server-feature-" + std::to_wstring(id);
}

const legacy_server_feature* find_legacy_server_feature(
    const std::vector<legacy_server_feature>& features,
    std::uint32_t id) {
  const auto match = std::lower_bound(
      features.begin(),
      features.end(),
      id,
      [](const legacy_server_feature& feature, std::uint32_t candidate) {
        return feature.id < candidate;
      });
  return match != features.end() && match->id == id ? &*match : nullptr;
}

bool is_legacy_role_service(
    const std::vector<legacy_server_feature>& features,
    std::uint32_t parent_id) {
  for (std::size_t depth = 0; parent_id != 0 && depth < 32; ++depth) {
    if (is_legacy_server_role(parent_id)) return true;
    const auto* parent = find_legacy_server_feature(features, parent_id);
    if (parent == nullptr || parent->parent_id == parent_id) return false;
    parent_id = parent->parent_id;
  }
  return false;
}

std::optional<std::vector<installed_server_feature>>
read_legacy_installed_server_features(std::string& failure_reason) {
  com_scope com;
  if (!com.initialized) {
    failure_reason = "com_initialization_failed";
    return std::nullopt;
  }
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
  if (FAILED(security) && security != RPC_E_TOO_LATE) {
    failure_reason = "com_security_failed";
    return std::nullopt;
  }

  Microsoft::WRL::ComPtr<IWbemLocator> locator;
  if (FAILED(CoCreateInstance(
          CLSID_WbemLocator,
          nullptr,
          CLSCTX_INPROC_SERVER,
          IID_PPV_ARGS(&locator)))) {
    failure_reason = "wmi_locator_failed";
    return std::nullopt;
  }
  BSTR namespace_path = SysAllocString(L"ROOT\\CIMV2");
  if (namespace_path == nullptr) {
    failure_reason = "allocation_failed";
    return std::nullopt;
  }
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
  if (FAILED(connection) || !services) {
    failure_reason = "server_feature_fallback_unavailable";
    return std::nullopt;
  }
  if (FAILED(CoSetProxyBlanket(
          services.Get(),
          RPC_C_AUTHN_WINNT,
          RPC_C_AUTHZ_NONE,
          nullptr,
          RPC_C_AUTHN_LEVEL_CALL,
          RPC_C_IMP_LEVEL_IMPERSONATE,
          nullptr,
          EOAC_NONE))) {
    failure_reason = "wmi_proxy_failed";
    return std::nullopt;
  }

  BSTR language = SysAllocString(L"WQL");
  BSTR statement = SysAllocString(
      L"SELECT ID, ParentID, Name FROM Win32_ServerFeature");
  if (language == nullptr || statement == nullptr) {
    if (language != nullptr) SysFreeString(language);
    if (statement != nullptr) SysFreeString(statement);
    failure_reason = "allocation_failed";
    return std::nullopt;
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
  if (FAILED(query_result) || !rows) {
    failure_reason = "server_feature_fallback_query_failed";
    return std::nullopt;
  }

  std::vector<legacy_server_feature> legacy_features;
  const auto query_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(60);
  for (;;) {
    Microsoft::WRL::ComPtr<IWbemClassObject> row;
    ULONG returned = 0;
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        query_deadline - std::chrono::steady_clock::now());
    if (remaining <= std::chrono::milliseconds::zero()) {
      failure_reason = "server_feature_fallback_query_timeout";
      return std::nullopt;
    }
    const auto maximum_wait = std::chrono::milliseconds(5'000);
    const auto wait_time = static_cast<LONG>(
        (remaining < maximum_wait ? remaining : maximum_wait).count());
    const HRESULT next = rows->Next(
        wait_time,
        1,
        row.ReleaseAndGetAddressOf(),
        &returned);
    if (next == WBEM_S_FALSE && returned == 0) break;
    if (FAILED(next)) {
      failure_reason = "server_feature_fallback_query_failed";
      return std::nullopt;
    }
    if (returned == 0 || !row) {
      if (next == WBEM_S_TIMEDOUT) continue;
      failure_reason = "server_feature_fallback_result_invalid";
      return std::nullopt;
    }
    const auto id = wmi_uint32(row.Get(), L"ID");
    const auto parent_id = wmi_uint32(row.Get(), L"ParentID");
    const auto display_name = wmi_string(row.Get(), L"Name");
    if (!id || !parent_id || display_name.empty()) {
      failure_reason = "server_feature_fallback_result_invalid";
      return std::nullopt;
    }
    if (legacy_features.size() >= 512) {
      failure_reason = "item_limit_exceeded";
      return std::nullopt;
    }
    if (display_name.size() > 255) {
      failure_reason = "value_limit_exceeded";
      return std::nullopt;
    }
    legacy_features.push_back({*id, *parent_id, display_name});
  }

  std::sort(
      legacy_features.begin(),
      legacy_features.end(),
      [](const auto& left, const auto& right) { return left.id < right.id; });
  legacy_features.erase(
      std::unique(
          legacy_features.begin(),
          legacy_features.end(),
          [](const auto& left, const auto& right) { return left.id == right.id; }),
      legacy_features.end());

  std::vector<installed_server_feature> features;
  features.reserve(legacy_features.size());
  for (const auto& feature : legacy_features) {
    std::string type = "feature";
    if (is_legacy_server_role(feature.id)) {
      type = "role";
    } else if (is_legacy_role_service(legacy_features, feature.parent_id)) {
      type = "role-service";
    }
    features.push_back({
        legacy_server_feature_name(feature.id),
        feature.display_name,
        feature.parent_id == 0
            ? std::wstring{}
            : legacy_server_feature_name(feature.parent_id),
        std::move(type),
    });
  }
  failure_reason.clear();
  return features;
}

std::optional<std::vector<installed_server_feature>> read_installed_server_features(
    std::string& failure_reason) {
  failure_reason.clear();
  com_scope com;
  if (!com.initialized) {
    failure_reason = "com_initialization_failed";
    return std::nullopt;
  }
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
  if (FAILED(security) && security != RPC_E_TOO_LATE) {
    failure_reason = "com_security_failed";
    return std::nullopt;
  }

  Microsoft::WRL::ComPtr<IWbemLocator> locator;
  if (FAILED(CoCreateInstance(
          CLSID_WbemLocator,
          nullptr,
          CLSCTX_INPROC_SERVER,
          IID_PPV_ARGS(&locator)))) {
    failure_reason = "wmi_locator_failed";
    return std::nullopt;
  }
  BSTR namespace_path = SysAllocString(L"ROOT\\Windows\\ServerManager");
  if (namespace_path == nullptr) {
    failure_reason = "allocation_failed";
    return std::nullopt;
  }
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
  if (FAILED(connection) || !services) {
    failure_reason = "server_manager_provider_unavailable";
    return std::nullopt;
  }
  if (FAILED(CoSetProxyBlanket(
          services.Get(),
          RPC_C_AUTHN_WINNT,
          RPC_C_AUTHZ_NONE,
          nullptr,
          RPC_C_AUTHN_LEVEL_CALL,
          RPC_C_IMP_LEVEL_IMPERSONATE,
          nullptr,
          EOAC_NONE))) {
    failure_reason = "wmi_proxy_failed";
    return std::nullopt;
  }

  BSTR language = SysAllocString(L"WQL");
  BSTR statement = SysAllocString(
      L"SELECT UniqueName, DisplayName, ParentName, Type, State "
      L"FROM MSFT_ServerFeature WHERE State = 1");
  if (language == nullptr || statement == nullptr) {
    if (language != nullptr) SysFreeString(language);
    if (statement != nullptr) SysFreeString(statement);
    failure_reason = "allocation_failed";
    return std::nullopt;
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
  if (FAILED(query_result) || !rows) {
    failure_reason = "server_manager_query_failed";
    return std::nullopt;
  }

  std::vector<installed_server_feature> features;
  const auto query_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(60);
  for (;;) {
    Microsoft::WRL::ComPtr<IWbemClassObject> row;
    ULONG returned = 0;
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        query_deadline - std::chrono::steady_clock::now());
    if (remaining <= std::chrono::milliseconds::zero()) {
      failure_reason = "server_manager_query_timeout";
      return std::nullopt;
    }
    const auto maximum_wait = std::chrono::milliseconds(5'000);
    const auto wait_time = static_cast<LONG>(
        (remaining < maximum_wait ? remaining : maximum_wait).count());
    const HRESULT next = rows->Next(
        wait_time,
        1,
        row.ReleaseAndGetAddressOf(),
        &returned);
    if (next == WBEM_S_FALSE && returned == 0) break;
    if (FAILED(next)) {
      failure_reason = "server_manager_query_failed";
      return std::nullopt;
    }
    if (returned == 0 || !row) {
      if (next == WBEM_S_TIMEDOUT) continue;
      failure_reason = "server_manager_result_invalid";
      return std::nullopt;
    }
    const auto state = wmi_uint32(row.Get(), L"State");
    const auto type = wmi_uint32(row.Get(), L"Type");
    const auto unique_name = wmi_string(row.Get(), L"UniqueName");
    if (!state || *state != 1U || !type || unique_name.empty()) continue;
    std::string normalized_type;
    switch (*type) {
      case 0: normalized_type = "role"; break;
      case 1: normalized_type = "role-service"; break;
      case 2: normalized_type = "feature"; break;
      default: continue;
    }
    if (features.size() >= 512) {
      failure_reason = "item_limit_exceeded";
      return std::nullopt;
    }
    auto display_name = wmi_string(row.Get(), L"DisplayName");
    if (display_name.empty()) display_name = unique_name;
    const auto parent_name = wmi_string(row.Get(), L"ParentName");
    if (unique_name.size() > 255 || display_name.size() > 255 ||
        parent_name.size() > 255) {
      failure_reason = "value_limit_exceeded";
      return std::nullopt;
    }
    features.push_back({
        unique_name,
        std::move(display_name),
        parent_name,
        normalized_type,
    });
  }
  std::sort(features.begin(), features.end(), [](const auto& left, const auto& right) {
    return left.unique_name < right.unique_name;
  });
  features.erase(
      std::unique(features.begin(), features.end(), [](const auto& left, const auto& right) {
        return left.unique_name == right.unique_name;
      }),
      features.end());
  return features;
}

std::string installed_server_features_json(
    bool& collected,
    std::string& failure_reason) {
  auto features = read_installed_server_features(failure_reason);
  if (!features &&
      failure_reason != "allocation_failed" &&
      failure_reason != "item_limit_exceeded" &&
      failure_reason != "value_limit_exceeded" &&
      failure_reason != "payload_limit_exceeded") {
    features = read_legacy_installed_server_features(failure_reason);
  }
  collected = false;
  if (!features) return "[]";
  constexpr std::streamoff k_max_serialized_feature_bytes = 32'768;
  std::ostringstream json;
  json << '[';
  for (std::size_t index = 0; index < features->size(); ++index) {
    if (index != 0) json << ',';
    const auto& feature = (*features)[index];
    json << "{\"name\":\"" << json_escape(utf8(feature.unique_name))
         << "\",\"display_name\":\"" << json_escape(utf8(feature.display_name))
         << "\",\"parent_name\":\"" << json_escape(utf8(feature.parent_name))
         << "\",\"type\":\"" << feature.type << "\"}";
    if (json.tellp() > k_max_serialized_feature_bytes) {
      failure_reason = "payload_limit_exceeded";
      return "[]";
    }
  }
  json << ']';
  collected = true;
  failure_reason.clear();
  return json.str();
}

std::wstring fqdn(const std::wstring& hostname, const windows_identity& identity) {
  if (!identity.part_of_domain || identity.domain.empty()) return {};
  const auto dns_name = computer_name_ex(ComputerNameDnsFullyQualified);
  if (dns_name.find(L'.') != std::wstring::npos) return dns_name;
  if (hostname.find(L'.') != std::wstring::npos) return hostname;
  return hostname + L"." + identity.domain;
}

std::string adapter_status(IF_OPER_STATUS status) {
  switch (status) {
    case IfOperStatusUp: return "up";
    case IfOperStatusDown: return "down";
    case IfOperStatusTesting: return "testing";
    case IfOperStatusDormant: return "dormant";
    case IfOperStatusNotPresent: return "not-present";
    case IfOperStatusLowerLayerDown: return "lower-layer-down";
    default: return "unknown";
  }
}

std::string socket_address(const SOCKADDR* address) {
  if (address == nullptr) return {};
  wchar_t buffer[INET6_ADDRSTRLEN]{};
  if (address->sa_family == AF_INET) {
    const auto* ipv4 = reinterpret_cast<const SOCKADDR_IN*>(address);
    if (InetNtopW(AF_INET, &ipv4->sin_addr, buffer, INET6_ADDRSTRLEN) != nullptr) {
      return utf8(buffer);
    }
  }
  if (address->sa_family == AF_INET6) {
    const auto* ipv6 = reinterpret_cast<const SOCKADDR_IN6*>(address);
    if (InetNtopW(AF_INET6, &ipv6->sin6_addr, buffer, INET6_ADDRSTRLEN) != nullptr) {
      return utf8(buffer);
    }
  }
  return {};
}

std::string mac_address(const IP_ADAPTER_ADDRESSES& adapter) {
  if (adapter.PhysicalAddressLength == 0) return {};
  std::ostringstream value;
  value << std::hex << std::setfill('0');
  for (ULONG index = 0; index < adapter.PhysicalAddressLength; ++index) {
    if (index != 0) value << ':';
    value << std::setw(2) << static_cast<unsigned>(adapter.PhysicalAddress[index]);
  }
  return value.str();
}

std::string string_list_json(IP_ADAPTER_DNS_SERVER_ADDRESS* address) {
  std::ostringstream json;
  json << '[';
  std::size_t count = 0;
  for (; address != nullptr && count < 64; address = address->Next) {
    const auto value = socket_address(address->Address.lpSockaddr);
    if (value.empty()) continue;
    if (count++ != 0) json << ',';
    json << '"' << json_escape(value) << '"';
  }
  json << ']';
  return json.str();
}

std::string gateway_list_json(IP_ADAPTER_GATEWAY_ADDRESS_LH* address) {
  std::ostringstream json;
  json << '[';
  std::size_t count = 0;
  for (; address != nullptr && count < 64; address = address->Next) {
    const auto value = socket_address(address->Address.lpSockaddr);
    if (value.empty()) continue;
    if (count++ != 0) json << ',';
    json << '"' << json_escape(value) << '"';
  }
  json << ']';
  return json.str();
}

std::string unicast_list_json(IP_ADAPTER_UNICAST_ADDRESS_LH* address) {
  std::ostringstream json;
  json << '[';
  std::size_t count = 0;
  for (; address != nullptr && count < 64; address = address->Next) {
    const auto value = socket_address(address->Address.lpSockaddr);
    if (value.empty()) continue;
    if (count++ != 0) json << ',';
    json << "{\"address\":\"" << json_escape(value)
         << "\",\"prefix_length\":" << static_cast<unsigned>(address->OnLinkPrefixLength)
         << '}';
  }
  json << ']';
  return json.str();
}

std::string network_interfaces_json() {
  ULONG size = 16 * 1024;
  std::vector<unsigned char> buffer(size);
  constexpr ULONG flags =
      GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS |
      GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
  ULONG result = GetAdaptersAddresses(
      AF_UNSPEC,
      flags,
      nullptr,
      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()),
      &size);
  if (result == ERROR_BUFFER_OVERFLOW && size <= 1024 * 1024) {
    buffer.resize(size);
    result = GetAdaptersAddresses(
        AF_UNSPEC,
        flags,
        nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()),
        &size);
  }
  if (result != NO_ERROR) return "[]";

  std::ostringstream json;
  json << '[';
  std::size_t count = 0;
  for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
       adapter != nullptr && count < 64;
       adapter = adapter->Next) {
    if (count++ != 0) json << ',';
    json << "{\"interface_id\":\""
         << json_escape(adapter->AdapterName == nullptr ? "" : adapter->AdapterName)
         << "\",\"name\":\""
         << json_escape(utf8(adapter->FriendlyName == nullptr ? L"" : adapter->FriendlyName))
         << "\",\"description\":\""
         << json_escape(utf8(adapter->Description == nullptr ? L"" : adapter->Description))
         << "\",\"mac_address\":\"" << mac_address(*adapter)
         << "\",\"status\":\"" << adapter_status(adapter->OperStatus)
         << "\",\"transmit_link_speed_bps\":"
         << (adapter->TransmitLinkSpeed <= INT64_MAX ? adapter->TransmitLinkSpeed : 0)
         << ",\"receive_link_speed_bps\":"
         << (adapter->ReceiveLinkSpeed <= INT64_MAX ? adapter->ReceiveLinkSpeed : 0)
         << ",\"dhcp_enabled\":"
         << ((adapter->Flags & IP_ADAPTER_DHCP_ENABLED) != 0 ? "true" : "false")
         << ",\"dns_suffix\":\""
         << json_escape(utf8(adapter->DnsSuffix == nullptr ? L"" : adapter->DnsSuffix))
         << "\",\"addresses\":" << unicast_list_json(adapter->FirstUnicastAddress)
         << ",\"gateways\":" << gateway_list_json(adapter->FirstGatewayAddress)
         << ",\"dns_servers\":" << string_list_json(adapter->FirstDnsServerAddress)
         << '}';
  }
  json << ']';
  return json.str();
}

bool contains_case_insensitive(std::wstring value, std::wstring_view needle) {
  std::transform(value.begin(), value.end(), value.begin(), [](wchar_t character) {
    return static_cast<wchar_t>(std::towlower(character));
  });
  return value.find(needle) != std::wstring::npos;
}

std::string machine_type(
    const windows_identity& identity,
    const std::wstring& physical_host) {
  if (!physical_host.empty()) return "virtual";
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
  const auto hostname = computer_name();
  const auto physical_host = registry_string_at(
      L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
      L"PhysicalHostNameFullyQualified");
  bool roles_features_collected = false;
  std::string roles_features_error;
  const auto roles_features = installed_server_features_json(
      roles_features_collected,
      roles_features_error);
  std::ostringstream json;
  json << "{\"schema_version\":\"1\",\"pack\":\"windows-server-core\","
       << "\"agent_gateway_port\":" << ipms::agent::k_default_agent_gateway_port << ","
       << "\"hostname\":\"" << json_escape(utf8(hostname)) << "\","
       << "\"fqdn\":\"" << json_escape(utf8(fqdn(hostname, identity))) << "\","
       << "\"domain_name\":\"" << json_escape(utf8(identity.domain)) << "\","
       << "\"os_product\":\"" << json_escape(utf8(product_name)) << "\","
       << "\"os_name\":\"" << json_escape(utf8(operating_system)) << "\","
       << "\"os_version\":\"" << json_escape(utf8(identity.os_version)) << "\","
       << "\"os_build\":\"" << json_escape(utf8(registry_string(L"CurrentBuildNumber"))) << "\","
       << "\"architecture\":\"" << (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "other") << "\","
       << "\"manufacturer\":\"" << json_escape(utf8(identity.manufacturer)) << "\","
       << "\"model\":\"" << json_escape(utf8(identity.model)) << "\","
       << "\"machine_type\":\"" << machine_type(identity, physical_host) << "\","
       << "\"hypervisor_host\":\"" << json_escape(utf8(physical_host)) << "\","
       << "\"logical_processors\":" << system_info.dwNumberOfProcessors << ","
       << "\"memory_total_bytes\":" << memory.ullTotalPhys << ","
       << "\"installed_roles_features_status\":\""
       << (roles_features_collected ? "collected" : "unavailable") << "\","
       << "\"installed_roles_features_error\":\""
       << json_escape(roles_features_error) << "\","
       << "\"installed_roles_features\":" << roles_features << ","
       << "\"network_interfaces\":" << network_interfaces_json() << "}";
  return json.str();
}
}  // namespace ipms::agent::windows
