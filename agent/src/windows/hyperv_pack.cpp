#include "ipms/agent/hyperv_pack.hpp"

#include <windows.h>
#include <winsvc.h>
#include <wbemidl.h>
#include <wrl/client.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Microsoft::WRL::ComPtr;

constexpr std::size_t k_max_virtual_machines = 128;
constexpr std::size_t k_max_related_rows = 1024;
constexpr std::size_t k_max_ip_addresses = 64;
constexpr std::size_t k_max_json_bytes = 40 * 1024;

struct com_scope {
  bool initialized{false};
  com_scope() {
    const HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    initialized = SUCCEEDED(result);
  }
  ~com_scope() {
    if (initialized) CoUninitialize();
  }
};

struct virtual_machine {
  std::string source_id;
  std::string name;
  std::string state;
  std::optional<std::uint64_t> vcpu_count;
  std::optional<std::uint64_t> memory_bytes;
  std::optional<std::uint64_t> uptime_seconds;
  std::string configuration_version;
  std::vector<std::string> ip_addresses;
};

std::string utf8(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(
      CP_UTF8,
      0,
      value.data(),
      static_cast<int>(value.size()),
      nullptr,
      0,
      nullptr,
      nullptr);
  if (size <= 0) return {};
  std::string result(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(
      CP_UTF8,
      0,
      value.data(),
      static_cast<int>(value.size()),
      result.data(),
      size,
      nullptr,
      nullptr);
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
      default:
        if (character < 0x20) escaped << '?';
        else escaped << static_cast<char>(character);
    }
  }
  return escaped.str();
}

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

std::optional<std::uint64_t> wmi_uint64(
    IWbemClassObject* object,
    const wchar_t* property) {
  VARIANT value{};
  VariantInit(&value);
  const HRESULT result = object->Get(property, 0, &value, nullptr, nullptr);
  std::optional<std::uint64_t> number;
  if (SUCCEEDED(result)) {
    switch (value.vt) {
      case VT_UI1: number = value.bVal; break;
      case VT_UI2: number = value.uiVal; break;
      case VT_UI4: number = value.ulVal; break;
      case VT_UI8: number = value.ullVal; break;
      case VT_I1:
        if (value.cVal >= 0) number = static_cast<std::uint64_t>(value.cVal);
        break;
      case VT_I2:
        if (value.iVal >= 0) number = static_cast<std::uint64_t>(value.iVal);
        break;
      case VT_I4:
        if (value.lVal >= 0) number = static_cast<std::uint64_t>(value.lVal);
        break;
      case VT_I8:
        if (value.llVal >= 0) number = static_cast<std::uint64_t>(value.llVal);
        break;
      case VT_BSTR:
        if (value.bstrVal != nullptr) {
          wchar_t* end = nullptr;
          const auto parsed = std::wcstoull(value.bstrVal, &end, 10);
          if (end != value.bstrVal && *end == L'\0') number = parsed;
        }
        break;
      default: break;
    }
  }
  VariantClear(&value);
  return number;
}

std::vector<std::wstring> wmi_string_array(
    IWbemClassObject* object,
    const wchar_t* property) {
  VARIANT value{};
  VariantInit(&value);
  const HRESULT result = object->Get(property, 0, &value, nullptr, nullptr);
  std::vector<std::wstring> values;
  if (SUCCEEDED(result) && value.vt == (VT_ARRAY | VT_BSTR) && value.parray) {
    LONG lower = 0;
    LONG upper = -1;
    if (SUCCEEDED(SafeArrayGetLBound(value.parray, 1, &lower)) &&
        SUCCEEDED(SafeArrayGetUBound(value.parray, 1, &upper))) {
      for (LONG index = lower;
           index <= upper && values.size() < k_max_ip_addresses;
           ++index) {
        BSTR item = nullptr;
        if (SUCCEEDED(SafeArrayGetElement(value.parray, &index, &item)) && item) {
          values.emplace_back(item, SysStringLen(item));
          SysFreeString(item);
        }
      }
    }
  }
  VariantClear(&value);
  return values;
}

bool is_guid(std::string_view value) {
  if (value.size() != 36) return false;
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (value[index] != '-') return false;
      continue;
    }
    const auto character = static_cast<unsigned char>(value[index]);
    if (!std::isxdigit(character)) return false;
  }
  return true;
}

std::string normalized_guid(const std::wstring& value) {
  auto candidate = utf8(value);
  if (candidate.size() == 38 && candidate.front() == '{' && candidate.back() == '}') {
    candidate = candidate.substr(1, 36);
  }
  if (!is_guid(candidate)) return {};
  std::transform(
      candidate.begin(),
      candidate.end(),
      candidate.begin(),
      [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  return candidate;
}

std::string guid_from_instance_id(const std::wstring& value) {
  const auto text = utf8(value);
  for (std::size_t index = 0; index + 36 <= text.size(); ++index) {
    const std::string_view candidate(text.data() + index, 36);
    if (!is_guid(candidate)) continue;
    auto result = std::string(candidate);
    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return result;
  }
  return {};
}

std::string normalized_state(std::uint64_t enabled_state) {
  switch (enabled_state) {
    case 2: return "running";
    case 3: return "stopped";
    case 4: return "stopping";
    case 6: return "offline";
    case 9: return "quiesced";
    case 10: return "starting";
    case 32768: return "paused";
    case 32769: return "suspended";
    case 32773: return "saving";
    case 32774: return "stopping";
    case 32776: return "pausing";
    case 32777: return "resuming";
    default: return "unknown";
  }
}

bool hyperv_service_installed() {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) return false;
  SC_HANDLE service = OpenServiceW(manager, L"vmms", SERVICE_QUERY_STATUS);
  const bool installed = service != nullptr;
  if (service) CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return installed;
}

ComPtr<IEnumWbemClassObject> execute_query(
    IWbemServices* services,
    const wchar_t* query) {
  BSTR language = SysAllocString(L"WQL");
  BSTR statement = SysAllocString(query);
  if (!language || !statement) {
    if (language) SysFreeString(language);
    if (statement) SysFreeString(statement);
    return {};
  }
  ComPtr<IEnumWbemClassObject> rows;
  const HRESULT result = services->ExecQuery(
      language,
      statement,
      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
      nullptr,
      &rows);
  SysFreeString(language);
  SysFreeString(statement);
  return SUCCEEDED(result) ? rows : ComPtr<IEnumWbemClassObject>{};
}

template <typename Consumer>
bool consume_rows(
    IEnumWbemClassObject* rows,
    std::size_t limit,
    const std::chrono::steady_clock::time_point deadline,
    Consumer consumer) {
  std::size_t count = 0;
  for (;;) {
    if (std::chrono::steady_clock::now() >= deadline || count > limit) return false;
    ComPtr<IWbemClassObject> row;
    ULONG returned = 0;
    const HRESULT next = rows->Next(
        2'000,
        1,
        row.ReleaseAndGetAddressOf(),
        &returned);
    if (next == WBEM_S_FALSE && returned == 0) return true;
    if (next == WBEM_S_TIMEDOUT && returned == 0) continue;
    if (FAILED(next) || returned != 1 || !row || count == limit) return false;
    ++count;
    consumer(row.Get());
  }
}

std::string virtual_machines_json(const std::map<std::string, virtual_machine>& vms) {
  std::ostringstream json;
  json << '[';
  std::size_t index = 0;
  for (const auto& [_, vm] : vms) {
    if (index++ != 0) json << ',';
    json << "{\"source_id\":\"" << json_escape(vm.source_id)
         << "\",\"name\":\"" << json_escape(vm.name)
         << "\",\"state\":\"" << vm.state << "\",\"vcpu_count\":";
    if (vm.vcpu_count) json << *vm.vcpu_count;
    else json << "null";
    json << ",\"memory_bytes\":";
    if (vm.memory_bytes) json << *vm.memory_bytes;
    else json << "null";
    json << ",\"uptime_seconds\":";
    if (vm.uptime_seconds) json << *vm.uptime_seconds;
    else json << "null";
    json << ",\"configuration_version\":\""
         << json_escape(vm.configuration_version) << "\",\"ip_addresses\":[";
    for (std::size_t ip_index = 0; ip_index < vm.ip_addresses.size(); ++ip_index) {
      if (ip_index != 0) json << ',';
      json << '"' << json_escape(vm.ip_addresses[ip_index]) << '"';
    }
    json << "]}";
  }
  json << ']';
  return json.str();
}

}  // namespace

namespace ipms::agent::windows {

hyperv_inventory_result collect_hyperv_inventory() {
  if (!hyperv_service_installed()) return {"not-applicable", "", "[]"};

  com_scope com;
  if (!com.initialized) return {"unavailable", "com_initialization_failed", "[]"};
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
    return {"unavailable", "com_security_failed", "[]"};
  }

  ComPtr<IWbemLocator> locator;
  if (FAILED(CoCreateInstance(
          CLSID_WbemLocator,
          nullptr,
          CLSCTX_INPROC_SERVER,
          IID_PPV_ARGS(&locator)))) {
    return {"unavailable", "wmi_locator_failed", "[]"};
  }
  BSTR namespace_path = SysAllocString(L"ROOT\\Virtualization\\V2");
  if (!namespace_path) return {"unavailable", "allocation_failed", "[]"};
  ComPtr<IWbemServices> services;
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
    return {"unavailable", "hyperv_provider_unavailable", "[]"};
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
    return {"unavailable", "wmi_proxy_failed", "[]"};
  }

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(45);
  std::map<std::string, virtual_machine> vms;
  auto systems = execute_query(
      services.Get(),
      L"SELECT Name, ElementName, EnabledState, OnTimeInMilliseconds "
      L"FROM Msvm_ComputerSystem");
  if (!systems || !consume_rows(
          systems.Get(),
          k_max_virtual_machines + 1,
          deadline,
          [&vms](IWbemClassObject* row) {
            const auto id = normalized_guid(wmi_string(row, L"Name"));
            if (id.empty()) return;
            const auto name = utf8(wmi_string(row, L"ElementName"));
            if (name.empty() || name.size() > 255) return;
            const auto enabled_state = wmi_uint64(row, L"EnabledState").value_or(0);
            const auto uptime_ms = wmi_uint64(row, L"OnTimeInMilliseconds");
            vms.emplace(
                id,
                virtual_machine{
                    id,
                    name,
                    normalized_state(enabled_state),
                    std::nullopt,
                    std::nullopt,
                    uptime_ms ? std::optional<std::uint64_t>(*uptime_ms / 1000)
                              : std::nullopt,
                    "",
                    {},
                });
          }) ||
      vms.size() > k_max_virtual_machines) {
    return {"unavailable", "hyperv_system_query_failed", "[]"};
  }

  auto settings = execute_query(
      services.Get(),
      L"SELECT VirtualSystemIdentifier, VirtualSystemType, Version "
      L"FROM Msvm_VirtualSystemSettingData");
  if (!settings || !consume_rows(
          settings.Get(),
          k_max_related_rows,
          deadline,
          [&vms](IWbemClassObject* row) {
            const auto type = wmi_string(row, L"VirtualSystemType");
            if (_wcsicmp(type.c_str(), L"Microsoft:Hyper-V:System:Realized") != 0) return;
            const auto id = normalized_guid(
                wmi_string(row, L"VirtualSystemIdentifier"));
            const auto match = vms.find(id);
            if (match == vms.end()) return;
            const auto version = utf8(wmi_string(row, L"Version"));
            if (version.size() <= 64) match->second.configuration_version = version;
          })) {
    return {"unavailable", "hyperv_settings_query_failed", "[]"};
  }

  auto processors = execute_query(
      services.Get(),
      L"SELECT InstanceID, VirtualQuantity FROM Msvm_ProcessorSettingData");
  if (!processors || !consume_rows(
          processors.Get(),
          k_max_related_rows,
          deadline,
          [&vms](IWbemClassObject* row) {
            const auto match = vms.find(guid_from_instance_id(
                wmi_string(row, L"InstanceID")));
            if (match == vms.end()) return;
            const auto quantity = wmi_uint64(row, L"VirtualQuantity");
            if (quantity && *quantity <= 65'535) match->second.vcpu_count = quantity;
          })) {
    return {"unavailable", "hyperv_processor_query_failed", "[]"};
  }

  auto memory = execute_query(
      services.Get(),
      L"SELECT InstanceID, VirtualQuantity FROM Msvm_MemorySettingData");
  if (!memory || !consume_rows(
          memory.Get(),
          k_max_related_rows,
          deadline,
          [&vms](IWbemClassObject* row) {
            const auto match = vms.find(guid_from_instance_id(
                wmi_string(row, L"InstanceID")));
            if (match == vms.end()) return;
            const auto quantity_mb = wmi_uint64(row, L"VirtualQuantity");
            if (quantity_mb && *quantity_mb <= (UINT64_MAX / (1024 * 1024))) {
              match->second.memory_bytes = *quantity_mb * 1024 * 1024;
            }
          })) {
    return {"unavailable", "hyperv_memory_query_failed", "[]"};
  }

  auto networks = execute_query(
      services.Get(),
      L"SELECT InstanceID, IPAddresses "
      L"FROM Msvm_GuestNetworkAdapterConfiguration");
  if (networks && !consume_rows(
          networks.Get(),
          k_max_related_rows,
          deadline,
          [&vms](IWbemClassObject* row) {
            const auto match = vms.find(guid_from_instance_id(
                wmi_string(row, L"InstanceID")));
            if (match == vms.end()) return;
            for (const auto& address : wmi_string_array(row, L"IPAddresses")) {
              const auto value = utf8(address);
              if (value.empty() || value.size() > 64) continue;
              if (std::find(
                      match->second.ip_addresses.begin(),
                      match->second.ip_addresses.end(),
                      value) == match->second.ip_addresses.end() &&
                  match->second.ip_addresses.size() < k_max_ip_addresses) {
                match->second.ip_addresses.push_back(value);
              }
            }
          })) {
    return {"unavailable", "hyperv_network_query_failed", "[]"};
  }

  for (auto& [_, vm] : vms) {
    std::sort(vm.ip_addresses.begin(), vm.ip_addresses.end());
  }
  const auto json = virtual_machines_json(vms);
  if (json.size() > k_max_json_bytes) {
    return {"unavailable", "payload_limit_exceeded", "[]"};
  }
  return {"collected", "", json};
}

}  // namespace ipms::agent::windows
