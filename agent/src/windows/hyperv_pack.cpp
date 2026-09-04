#include "ipms/agent/hyperv_pack.hpp"

#include <windows.h>
#include <winsvc.h>
#include <wbemidl.h>
#include <wincodec.h>
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
#include <thread>
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

std::wstring wmi_object_path(IWbemClassObject* object) {
  auto path = wmi_string(object, L"__PATH");
  if (path.empty()) path = wmi_string(object, L"__RELPATH");
  return path;
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
    case 9: return "paused";
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

std::optional<std::uint16_t> requested_state_for_action(const std::string& action) {
  if (action == "start") return static_cast<std::uint16_t>(2);
  if (action == "stop") return static_cast<std::uint16_t>(3);
  if (action == "pause") return static_cast<std::uint16_t>(9);
  if (action == "resume") return static_cast<std::uint16_t>(2);
  return std::nullopt;
}

std::string expected_state_for_action(const std::string& action) {
  if (action == "start" || action == "resume") return "running";
  if (action == "shutdown" || action == "stop") return "stopped";
  if (action == "pause") return "paused";
  return {};
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

struct virtual_machine_lookup {
  ComPtr<IWbemClassObject> system;
  bool query_succeeded{false};
  bool identity_conflict{false};
  std::size_t rows_seen{0};
  std::size_t identifier_rows{0};
  std::size_t name_matches{0};
};

virtual_machine_lookup find_virtual_machine(
    IWbemServices* services,
    const std::string& normalized_source_id,
    const std::string& expected_name) {
  auto rows = execute_query(
      services,
      L"SELECT Name, ElementName, EnabledState FROM Msvm_ComputerSystem");
  if (!rows) return {};
  ComPtr<IWbemClassObject> identity_match;
  bool identity_conflict = false;
  std::size_t rows_seen = 0;
  std::size_t identifier_rows = 0;
  std::size_t name_matches = 0;
  const bool completed = consume_rows(
      rows.Get(),
      k_max_virtual_machines + 1,
      std::chrono::steady_clock::now() + std::chrono::seconds(10),
      [&identity_match,
       &identity_conflict,
       &rows_seen,
       &identifier_rows,
       &name_matches,
       &normalized_source_id,
       &expected_name](IWbemClassObject* row) {
        ++rows_seen;
        const auto name_id = normalized_guid(wmi_string(row, L"Name"));
        const auto path_id = guid_from_instance_id(wmi_string(row, L"__PATH"));
        if (!name_id.empty() || !path_id.empty()) ++identifier_rows;
        if (utf8(wmi_string(row, L"ElementName")) == expected_name) ++name_matches;
        if (!identity_match &&
            (name_id == normalized_source_id || path_id == normalized_source_id)) {
          if (utf8(wmi_string(row, L"ElementName")) != expected_name) {
            identity_conflict = true;
          } else {
            identity_match = row;
          }
        }
      });
  return {
      identity_match,
      completed,
      identity_conflict,
      rows_seen,
      identifier_rows,
      name_matches,
  };
}

struct shutdown_component_lookup {
  ComPtr<IWbemClassObject> component;
  std::wstring object_path;
  bool query_succeeded{false};
};

std::wstring escaped_wmi_key_value(const std::wstring& value) {
  if (value.empty() || value.size() > 1'024) return {};
  std::wstring escaped;
  escaped.reserve(value.size() + 16);
  for (const wchar_t character : value) {
    if (character < 0x20 || character == 0x7f) return {};
    if (character == L'\\' || character == L'"') escaped.push_back(L'\\');
    escaped.push_back(character);
  }
  return escaped;
}

shutdown_component_lookup find_shutdown_component(
    IWbemServices* services,
    const std::string& normalized_source_id) {
  auto rows = execute_query(
      services,
      L"SELECT SystemName, DeviceID FROM Msvm_ShutdownComponent");
  if (!rows) return {};
  ComPtr<IWbemClassObject> match;
  std::wstring match_path;
  const bool completed = consume_rows(
      rows.Get(),
      k_max_virtual_machines + 1,
      std::chrono::steady_clock::now() + std::chrono::seconds(10),
      [&match, &match_path, &normalized_source_id](IWbemClassObject* row) {
        if (match) return;
        const auto system_name = wmi_string(row, L"SystemName");
        const auto device_id = wmi_string(row, L"DeviceID");
        auto id = normalized_guid(system_name);
        if (id.empty()) id = guid_from_instance_id(device_id);
        const auto escaped_system_name = escaped_wmi_key_value(system_name);
        const auto escaped_device_id = escaped_wmi_key_value(device_id);
        if (id == normalized_source_id && !escaped_system_name.empty() &&
            !escaped_device_id.empty()) {
          match = row;
          match_path =
              L"Msvm_ShutdownComponent.CreationClassName=\"Msvm_ShutdownComponent\","
              L"DeviceID=\"" + escaped_device_id +
              L"\",SystemCreationClassName=\"Msvm_ComputerSystem\",SystemName=\"" +
              escaped_system_name + L"\"";
        }
      });
  return {match, match_path, completed};
}

bool wait_for_virtual_machine_state(
    IWbemServices* services,
    const std::string& normalized_source_id,
    const std::string& expected_name,
    const std::string& expected_state,
    unsigned attempts) {
  for (unsigned attempt = 0; attempt < attempts; ++attempt) {
    std::this_thread::sleep_for(std::chrono::seconds(2));
    const auto refreshed =
        find_virtual_machine(services, normalized_source_id, expected_name);
    if (refreshed.query_succeeded && refreshed.system &&
        normalized_state(
            wmi_uint64(refreshed.system.Get(), L"EnabledState").value_or(0)) ==
            expected_state) {
      return true;
    }
  }
  return false;
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

struct hyperv_services {
  ComPtr<IWbemServices> value;
  std::string error;
};

hyperv_services connect_hyperv_services() {
  const HRESULT security = CoInitializeSecurity(
      nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
  if (FAILED(security) && security != RPC_E_TOO_LATE) return {{}, "com_security_failed"};
  ComPtr<IWbemLocator> locator;
  if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&locator)))) {
    return {{}, "wmi_locator_failed"};
  }
  BSTR namespace_path = SysAllocString(L"ROOT\\Virtualization\\V2");
  if (!namespace_path) return {{}, "allocation_failed"};
  ComPtr<IWbemServices> services;
  const HRESULT connection = locator->ConnectServer(
      namespace_path, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
  SysFreeString(namespace_path);
  if (FAILED(connection) || !services) return {{}, "hyperv_provider_unavailable"};
  if (FAILED(CoSetProxyBlanket(
          services.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE))) {
    return {{}, "wmi_proxy_failed"};
  }
  return {services, ""};
}

ComPtr<IWbemClassObject> find_related_device(
    IWbemServices* services,
    const wchar_t* class_name,
    const std::string& source_id) {
  std::wstring query = L"SELECT * FROM ";
  query += class_name;
  auto rows = execute_query(services, query.c_str());
  if (!rows) return {};
  ComPtr<IWbemClassObject> match;
  consume_rows(
      rows.Get(), k_max_related_rows,
      std::chrono::steady_clock::now() + std::chrono::seconds(10),
      [&match, &source_id](IWbemClassObject* row) {
        if (!match && normalized_guid(wmi_string(row, L"SystemName")) == source_id) {
          match = row;
        }
      });
  return match;
}

ComPtr<IWbemClassObject> find_realized_settings(
    IWbemServices* services,
    const std::string& source_id) {
  // Resolve the current setting object through the documented
  // Msvm_SettingsDefineState association. Scanning the whole settings class is
  // both ambiguous in the presence of checkpoints and bounded by our global
  // WMI row limit, which can hide a valid VM on larger hosts.
  const std::wstring vm_id(source_id.begin(), source_id.end());
  const std::wstring query =
      L"ASSOCIATORS OF {Msvm_ComputerSystem.CreationClassName=\"Msvm_ComputerSystem\","
      L"Name=\"" + vm_id +
      L"\"} WHERE AssocClass=Msvm_SettingsDefineState "
      L"ResultClass=Msvm_VirtualSystemSettingData "
      L"Role=ManagedElement ResultRole=SettingData";
  auto rows = execute_query(services, query.c_str());
  if (!rows) return {};
  ComPtr<IWbemClassObject> match;
  const bool completed = consume_rows(
      rows.Get(), 8,
      std::chrono::steady_clock::now() + std::chrono::seconds(10),
      [&match, &source_id](IWbemClassObject* row) {
        if (match || normalized_guid(wmi_string(row, L"VirtualSystemIdentifier")) != source_id) {
          return;
        }
        match = row;
      });
  return completed ? match : ComPtr<IWbemClassObject>{};
}

bool invoke_input_method(
    IWbemServices* services,
    IWbemClassObject* device,
    const wchar_t* class_name,
    const wchar_t* method,
    const std::vector<std::pair<const wchar_t*, VARIANT>>& parameters) {
  const auto path = wmi_string(device, L"__PATH");
  if (path.empty()) return false;
  ComPtr<IWbemClassObject> device_class;
  BSTR allocated_class = SysAllocString(class_name);
  if (!allocated_class) return false;
  const HRESULT class_result = services->GetObject(
      allocated_class, 0, nullptr, &device_class, nullptr);
  SysFreeString(allocated_class);
  if (FAILED(class_result) || !device_class) return false;
  ComPtr<IWbemClassObject> signature;
  BSTR allocated_method = SysAllocString(method);
  if (!allocated_method) return false;
  const HRESULT method_result = device_class->GetMethod(
      allocated_method, 0, &signature, nullptr);
  if (FAILED(method_result)) {
    SysFreeString(allocated_method);
    return false;
  }
  ComPtr<IWbemClassObject> input;
  if (signature && (FAILED(signature->SpawnInstance(0, &input)) || !input)) {
    SysFreeString(allocated_method);
    return false;
  }
  for (const auto& [name, value] : parameters) {
    if (!input || FAILED(input->Put(name, 0, const_cast<VARIANT*>(&value), 0))) {
      SysFreeString(allocated_method);
      return false;
    }
  }
  BSTR allocated_path = SysAllocString(path.c_str());
  if (!allocated_path) {
    SysFreeString(allocated_method);
    return false;
  }
  ComPtr<IWbemClassObject> output;
  const HRESULT result = services->ExecMethod(
      allocated_path, allocated_method, 0, nullptr, input.Get(), &output, nullptr);
  SysFreeString(allocated_path);
  SysFreeString(allocated_method);
  return SUCCEEDED(result) && output &&
         wmi_uint64(output.Get(), L"ReturnValue").value_or(1) == 0;
}

bool apply_console_input(
    IWbemServices* services,
    const std::string& source_id,
    const ipms::agent::windows::hyperv_console_input& input) {
  if (input.type == "key" || input.type == "secure_attention") {
    auto keyboard = find_related_device(services, L"Msvm_Keyboard", source_id);
    if (!keyboard) return false;
    if (input.type == "secure_attention") {
      return invoke_input_method(
          services, keyboard.Get(), L"Msvm_Keyboard", L"TypeCtrlAltDel", {});
    }
    VARIANT key{};
    VariantInit(&key);
    key.vt = VT_UI4;
    key.ulVal = input.key_code;
    return invoke_input_method(
        services,
        keyboard.Get(),
        L"Msvm_Keyboard",
        input.is_down ? L"PressKey" : L"ReleaseKey",
        {{L"keyCode", key}});
  }
  auto mouse = find_related_device(services, L"Msvm_SyntheticMouse", source_id);
  const wchar_t* mouse_class = L"Msvm_SyntheticMouse";
  if (!mouse) {
    mouse = find_related_device(services, L"Msvm_Ps2Mouse", source_id);
    mouse_class = L"Msvm_Ps2Mouse";
  }
  if (!mouse) return false;
  if (input.type == "mouse_move") {
    VARIANT horizontal{};
    VARIANT vertical{};
    VariantInit(&horizontal);
    VariantInit(&vertical);
    horizontal.vt = VT_I4;
    horizontal.lVal = input.x;
    vertical.vt = VT_I4;
    vertical.lVal = input.y;
    return invoke_input_method(
        services, mouse.Get(), mouse_class, L"SetAbsolutePosition",
        {{L"horizontalPosition", horizontal}, {L"verticalPosition", vertical}});
  }
  if (input.type == "mouse_button") {
    VARIANT button{};
    VARIANT down{};
    VariantInit(&button);
    VariantInit(&down);
    button.vt = VT_UI4;
    button.ulVal = input.button;
    down.vt = VT_BOOL;
    down.boolVal = input.is_down ? VARIANT_TRUE : VARIANT_FALSE;
    return invoke_input_method(
        services, mouse.Get(), mouse_class, L"SetButtonState",
        {{L"buttonIndex", button}, {L"isDown", down}});
  }
  if (input.type == "mouse_wheel") {
    VARIANT scroll{};
    VariantInit(&scroll);
    scroll.vt = VT_I4;
    scroll.lVal = input.delta;
    return invoke_input_method(
        services, mouse.Get(), mouse_class, L"SetScrollPosition",
        {{L"scrollPositionDelta", scroll}});
  }
  return false;
}

std::vector<std::uint8_t> encode_rgb565_png(
    const std::vector<std::uint8_t>& rgb565,
    std::uint16_t width,
    std::uint16_t height) {
  const std::size_t pixels = static_cast<std::size_t>(width) * height;
  if (rgb565.size() != pixels * 2) return {};
  std::vector<std::uint8_t> bgra(pixels * 4);
  for (std::size_t index = 0; index < pixels; ++index) {
    const std::uint16_t pixel = static_cast<std::uint16_t>(rgb565[index * 2]) |
                                (static_cast<std::uint16_t>(rgb565[index * 2 + 1]) << 8);
    bgra[index * 4] = static_cast<std::uint8_t>((pixel & 0x1f) * 255 / 31);
    bgra[index * 4 + 1] = static_cast<std::uint8_t>(((pixel >> 5) & 0x3f) * 255 / 63);
    bgra[index * 4 + 2] = static_cast<std::uint8_t>(((pixel >> 11) & 0x1f) * 255 / 31);
    bgra[index * 4 + 3] = 255;
  }
  ComPtr<IWICImagingFactory> factory;
  if (FAILED(CoCreateInstance(
          CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
          IID_PPV_ARGS(&factory)))) {
    return {};
  }
  ComPtr<IStream> stream;
  if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &stream))) return {};
  ComPtr<IWICBitmapEncoder> encoder;
  if (FAILED(factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder)) ||
      FAILED(encoder->Initialize(stream.Get(), WICBitmapEncoderNoCache))) {
    return {};
  }
  ComPtr<IWICBitmapFrameEncode> frame;
  ComPtr<IPropertyBag2> properties;
  if (FAILED(encoder->CreateNewFrame(&frame, &properties)) ||
      FAILED(frame->Initialize(properties.Get())) ||
      FAILED(frame->SetSize(width, height))) {
    return {};
  }
  WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
  if (FAILED(frame->SetPixelFormat(&format)) || format != GUID_WICPixelFormat32bppBGRA ||
      FAILED(frame->WritePixels(
          height,
          static_cast<UINT>(width) * 4,
          static_cast<UINT>(bgra.size()),
          bgra.data())) ||
      FAILED(frame->Commit()) || FAILED(encoder->Commit())) {
    return {};
  }
  HGLOBAL global = nullptr;
  if (FAILED(GetHGlobalFromStream(stream.Get(), &global)) || !global) return {};
  const auto size = GlobalSize(global);
  const auto* data = static_cast<const std::uint8_t*>(GlobalLock(global));
  if (!data || size == 0 || size > 1'500'000) {
    if (data) GlobalUnlock(global);
    return {};
  }
  std::vector<std::uint8_t> png(data, data + size);
  GlobalUnlock(global);
  return png;
}

std::string thumbnail_failure_code(std::uint64_t return_value) {
  switch (return_value) {
    case 4096: return "console_frame_job_started";
    case 32768: return "console_frame_provider_failed";
    case 32769: return "console_frame_access_denied";
    case 32770: return "console_frame_not_supported";
    case 32771: return "console_frame_status_unknown";
    case 32772: return "console_frame_timeout";
    case 32773: return "console_frame_invalid_parameter";
    case 32774: return "console_frame_system_in_use";
    case 32775: return "console_frame_invalid_state";
    case 32776: return "console_frame_incorrect_data_type";
    case 32777: return "console_frame_system_unavailable";
    case 32778: return "console_frame_out_of_memory";
    default: return "console_frame_provider_error";
  }
}

std::vector<std::uint8_t> capture_console_frame(
    IWbemServices* services,
    IWbemClassObject* settings,
    const std::string& source_id,
    std::uint16_t& width,
    std::uint16_t& height,
    std::string& failure_code) {
  const auto settings_path = wmi_object_path(settings);
  if (settings_path.empty()) {
    failure_code = "console_frame_setting_path_missing";
    return {};
  }
  ComPtr<IWbemClassObject> service_class;
  BSTR class_name = SysAllocString(L"Msvm_VirtualSystemManagementService");
  if (!class_name) {
    failure_code = "console_frame_allocation_failed";
    return {};
  }
  const HRESULT class_result = services->GetObject(
      class_name, 0, nullptr, &service_class, nullptr);
  SysFreeString(class_name);
  if (FAILED(class_result) || !service_class) {
    failure_code = "console_frame_service_class_missing";
    return {};
  }
  ComPtr<IWbemClassObject> signature;
  BSTR method = SysAllocString(L"GetVirtualSystemThumbnailImage");
  if (!method) {
    failure_code = "console_frame_allocation_failed";
    return {};
  }
  const HRESULT method_result = service_class->GetMethod(method, 0, &signature, nullptr);
  if (FAILED(method_result) || !signature) {
    SysFreeString(method);
    failure_code = "console_frame_method_missing";
    return {};
  }
  ComPtr<IWbemClassObject> input;
  if (FAILED(signature->SpawnInstance(0, &input)) || !input) {
    SysFreeString(method);
    failure_code = "console_frame_input_spawn_failed";
    return {};
  }
  VARIANT target{};
  VARIANT width_value{};
  VARIANT height_value{};
  VariantInit(&target);
  VariantInit(&width_value);
  VariantInit(&height_value);
  target.vt = VT_BSTR;
  target.bstrVal = SysAllocString(settings_path.c_str());
  // The spawned WMI method input object exposes these CIM uint16 values
  // through Automation-compatible signed 32-bit VARIANTs. The Hyper-V
  // provider rejects VT_UI2 here even though the MOF declaration is uint16.
  width_value.vt = VT_I4;
  width_value.lVal = width;
  height_value.vt = VT_I4;
  height_value.lVal = height;
  const bool put = target.bstrVal &&
                   SUCCEEDED(input->Put(L"TargetSystem", 0, &target, 0)) &&
                   SUCCEEDED(input->Put(L"WidthPixels", 0, &width_value, 0)) &&
                   SUCCEEDED(input->Put(L"HeightPixels", 0, &height_value, 0));
  VariantClear(&target);
  if (!put) {
    SysFreeString(method);
    failure_code = "console_frame_argument_failed";
    return {};
  }
  auto services_rows = execute_query(
      services, L"SELECT * FROM Msvm_VirtualSystemManagementService");
  ComPtr<IWbemClassObject> service;
  if (services_rows) {
    consume_rows(
        services_rows.Get(), 2,
        std::chrono::steady_clock::now() + std::chrono::seconds(5),
        [&service](IWbemClassObject* row) { if (!service) service = row; });
  }
  const auto service_path = service ? wmi_object_path(service.Get()) : L"";
  if (service_path.empty()) {
    SysFreeString(method);
    failure_code = "console_frame_service_instance_missing";
    return {};
  }
  BSTR allocated_path = SysAllocString(service_path.c_str());
  if (!allocated_path) {
    SysFreeString(method);
    failure_code = "console_frame_allocation_failed";
    return {};
  }
  ComPtr<IWbemClassObject> output;
  const HRESULT execution = services->ExecMethod(
      allocated_path, method, 0, nullptr, input.Get(), &output, nullptr);
  SysFreeString(allocated_path);
  SysFreeString(method);
  if (FAILED(execution) || !output) {
    failure_code = "console_frame_execution_failed";
    return {};
  }
  const auto return_value = wmi_uint64(output.Get(), L"ReturnValue").value_or(1);
  if (return_value != 0) {
    failure_code = thumbnail_failure_code(return_value);
    return {};
  }
  VARIANT image{};
  VariantInit(&image);
  if (FAILED(output->Get(L"ImageData", 0, &image, nullptr, nullptr)) ||
      image.vt != (VT_ARRAY | VT_UI1) || !image.parray) {
    VariantClear(&image);
    failure_code = "console_frame_image_missing";
    return {};
  }
  LONG lower = 0;
  LONG upper = -1;
  std::vector<std::uint8_t> rgb565;
  if (SUCCEEDED(SafeArrayGetLBound(image.parray, 1, &lower)) &&
      SUCCEEDED(SafeArrayGetUBound(image.parray, 1, &upper)) && upper >= lower) {
    const auto size = static_cast<std::size_t>(upper - lower + 1);
    auto decoded_width = width;
    auto decoded_height = height;
    if (size != static_cast<std::size_t>(decoded_width) * decoded_height * 2) {
      // Some supported Hyper-V providers return the current video-head buffer
      // even when a different thumbnail size was requested. Accept that fixed,
      // provider-owned result only when its documented current dimensions
      // account for the complete RGB565 payload.
      auto video_head = find_related_device(services, L"Msvm_VideoHead", source_id);
      const auto current_width = video_head
          ? wmi_uint64(video_head.Get(), L"CurrentHorizontalResolution")
          : std::nullopt;
      const auto current_height = video_head
          ? wmi_uint64(video_head.Get(), L"CurrentVerticalResolution")
          : std::nullopt;
      if (current_width && current_height && *current_width >= 160 &&
          *current_width <= 1920 && *current_height >= 120 &&
          *current_height <= 1200 &&
          size == static_cast<std::size_t>(*current_width) * *current_height * 2) {
        decoded_width = static_cast<std::uint16_t>(*current_width);
        decoded_height = static_cast<std::uint16_t>(*current_height);
      }
    }
    if (size == static_cast<std::size_t>(decoded_width) * decoded_height * 2) {
      rgb565.resize(size);
      for (LONG index = lower; index <= upper; ++index) {
        if (FAILED(SafeArrayGetElement(
                image.parray,
                &index,
                &rgb565[static_cast<std::size_t>(index - lower)]))) {
          rgb565.clear();
          failure_code = "console_frame_image_read_failed";
          break;
        }
      }
      width = decoded_width;
      height = decoded_height;
    } else {
      failure_code = "console_frame_size_" + std::to_string(size) +
                     "_expected_" +
                     std::to_string(static_cast<std::size_t>(width) * height * 2);
    }
  } else {
    failure_code = "console_frame_image_bounds_invalid";
  }
  VariantClear(&image);
  if (rgb565.empty()) return {};
  auto png = encode_rgb565_png(rgb565, width, height);
  if (png.empty()) failure_code = "console_frame_png_encode_failed";
  return png;
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

hyperv_action_result execute_hyperv_virtual_machine_action(
    const std::string& source_id,
    const std::string& expected_name,
    const std::string& action) {
  if (!is_guid(source_id)) return {false, "invalid_vm_identity"};
  auto normalized_source_id = source_id;
  std::transform(
      normalized_source_id.begin(),
      normalized_source_id.end(),
      normalized_source_id.begin(),
      [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  const auto requested_state = requested_state_for_action(action);
  const auto expected_state = expected_state_for_action(action);
  if ((action != "shutdown" && !requested_state) || expected_state.empty()) {
    return {false, "invalid_action"};
  }
  if (!hyperv_service_installed()) return {false, "hyperv_unavailable"};

  com_scope com;
  if (!com.initialized) return {false, "com_initialization_failed"};
  const HRESULT security = CoInitializeSecurity(
      nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
  if (FAILED(security) && security != RPC_E_TOO_LATE) return {false, "com_security_failed"};

  ComPtr<IWbemLocator> locator;
  if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&locator)))) {
    return {false, "wmi_locator_failed"};
  }
  BSTR namespace_path = SysAllocString(L"ROOT\\Virtualization\\V2");
  if (!namespace_path) return {false, "allocation_failed"};
  ComPtr<IWbemServices> services;
  const HRESULT connection = locator->ConnectServer(
      namespace_path, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
  SysFreeString(namespace_path);
  if (FAILED(connection) || !services) return {false, "hyperv_provider_unavailable"};
  if (FAILED(CoSetProxyBlanket(
          services.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE))) {
    return {false, "wmi_proxy_failed"};
  }

  const auto lookup =
      find_virtual_machine(services.Get(), normalized_source_id, expected_name);
  if (!lookup.query_succeeded) return {false, "vm_lookup_failed"};
  if (lookup.identity_conflict) return {false, "vm_identity_conflict"};
  if (!lookup.system) {
    return {
        false,
        "vm_not_found_r" + std::to_string(lookup.rows_seen) +
            "_i" + std::to_string(lookup.identifier_rows) +
            "_n" + std::to_string(lookup.name_matches),
    };
  }
  auto system = lookup.system;
  const auto current_state = normalized_state(
      wmi_uint64(system.Get(), L"EnabledState").value_or(0));
  if (current_state == expected_state) return {true, "already_in_requested_state"};
  const bool allowed =
      (action == "start" && current_state == "stopped") ||
      (action == "shutdown" && current_state == "running") ||
      (action == "stop" && (current_state == "running" || current_state == "paused")) ||
      (action == "pause" && current_state == "running") ||
      (action == "resume" && current_state == "paused");
  if (!allowed) return {false, "invalid_vm_state"};

  if (action == "shutdown") {
    const auto component_lookup =
        find_shutdown_component(services.Get(), normalized_source_id);
    if (!component_lookup.query_succeeded) {
      return {false, "guest_shutdown_lookup_failed"};
    }
    if (!component_lookup.component) return {false, "guest_shutdown_unavailable"};
    const auto component_path = component_lookup.object_path;
    if (component_path.empty()) return {false, "guest_shutdown_unavailable"};

    ComPtr<IWbemClassObject> component_class;
    BSTR component_class_name = SysAllocString(L"Msvm_ShutdownComponent");
    if (!component_class_name) return {false, "allocation_failed"};
    const HRESULT component_class_result = services->GetObject(
        component_class_name, 0, nullptr, &component_class, nullptr);
    SysFreeString(component_class_name);
    if (FAILED(component_class_result) || !component_class) {
      return {false, "guest_shutdown_contract_unavailable"};
    }
    ComPtr<IWbemClassObject> shutdown_signature;
    BSTR shutdown_method = SysAllocString(L"InitiateShutdown");
    if (!shutdown_method) return {false, "allocation_failed"};
    const HRESULT shutdown_method_result = component_class->GetMethod(
        shutdown_method, 0, &shutdown_signature, nullptr);
    if (FAILED(shutdown_method_result) || !shutdown_signature) {
      SysFreeString(shutdown_method);
      return {false, "guest_shutdown_contract_unavailable"};
    }
    ComPtr<IWbemClassObject> shutdown_input;
    if (FAILED(shutdown_signature->SpawnInstance(0, &shutdown_input)) ||
        !shutdown_input) {
      SysFreeString(shutdown_method);
      return {false, "guest_shutdown_input_failed"};
    }
    VARIANT force_value{};
    VariantInit(&force_value);
    force_value.vt = VT_BOOL;
    force_value.boolVal = VARIANT_FALSE;
    const HRESULT force_result =
        shutdown_input->Put(L"Force", 0, &force_value, 0);
    VariantClear(&force_value);
    VARIANT reason_value{};
    VariantInit(&reason_value);
    reason_value.vt = VT_BSTR;
    reason_value.bstrVal =
        SysAllocString(L"IPMS administrator requested a graceful shutdown.");
    const HRESULT reason_result = reason_value.bstrVal
                                      ? shutdown_input->Put(
                                            L"Reason", 0, &reason_value, 0)
                                      : E_OUTOFMEMORY;
    VariantClear(&reason_value);
    if (FAILED(force_result) || FAILED(reason_result)) {
      SysFreeString(shutdown_method);
      return {false, "guest_shutdown_input_failed"};
    }
    BSTR shutdown_path = SysAllocString(component_path.c_str());
    if (!shutdown_path) {
      SysFreeString(shutdown_method);
      return {false, "allocation_failed"};
    }
    ComPtr<IWbemClassObject> shutdown_output;
    const HRESULT shutdown_result = services->ExecMethod(
        shutdown_path,
        shutdown_method,
        0,
        nullptr,
        shutdown_input.Get(),
        &shutdown_output,
        nullptr);
    SysFreeString(shutdown_path);
    SysFreeString(shutdown_method);
    if (FAILED(shutdown_result) || !shutdown_output) {
      return {
          false,
          "guest_shutdown_execution_failed_" +
              std::to_string(static_cast<std::uint32_t>(shutdown_result)),
      };
    }
    const auto shutdown_return =
        wmi_uint64(shutdown_output.Get(), L"ReturnValue").value_or(1);
    if (shutdown_return != 0 && shutdown_return != 4096) {
      return {false, "guest_shutdown_rejected"};
    }
    return wait_for_virtual_machine_state(
               services.Get(), normalized_source_id, expected_name, expected_state, 90)
               ? hyperv_action_result{true, "state_confirmed"}
               : hyperv_action_result{false, "state_confirmation_timeout"};
  }

  const std::wstring object_path =
      L"Msvm_ComputerSystem.Name=\"" +
      std::wstring(normalized_source_id.begin(), normalized_source_id.end()) +
      L"\"";
  ComPtr<IWbemClassObject> class_object;
  BSTR class_name = SysAllocString(L"Msvm_ComputerSystem");
  if (!class_name) return {false, "allocation_failed"};
  const HRESULT class_result = services->GetObject(
      class_name, 0, nullptr, &class_object, nullptr);
  SysFreeString(class_name);
  if (FAILED(class_result) || !class_object) return {false, "action_contract_unavailable"};
  ComPtr<IWbemClassObject> input_signature;
  BSTR method_name = SysAllocString(L"RequestStateChange");
  if (!method_name) return {false, "allocation_failed"};
  const HRESULT method_result = class_object->GetMethod(
      method_name, 0, &input_signature, nullptr);
  if (FAILED(method_result) || !input_signature) {
    SysFreeString(method_name);
    return {false, "action_contract_unavailable"};
  }
  ComPtr<IWbemClassObject> input;
  if (FAILED(input_signature->SpawnInstance(0, &input)) || !input) {
    SysFreeString(method_name);
    return {false, "action_input_failed"};
  }
  VARIANT state_value{};
  VariantInit(&state_value);
  state_value.vt = VT_I4;
  state_value.lVal = static_cast<LONG>(*requested_state);
  const HRESULT put_result = input->Put(L"RequestedState", 0, &state_value, 0);
  VariantClear(&state_value);
  if (FAILED(put_result)) {
    SysFreeString(method_name);
    return {false, "action_input_failed"};
  }
  BSTR path = SysAllocString(object_path.c_str());
  if (!path) {
    SysFreeString(method_name);
    return {false, "allocation_failed"};
  }
  ComPtr<IWbemClassObject> output;
  const HRESULT execute_result = services->ExecMethod(
      path, method_name, 0, nullptr, input.Get(), &output, nullptr);
  SysFreeString(path);
  SysFreeString(method_name);
  if (FAILED(execute_result) || !output) return {false, "action_execution_failed"};
  const auto return_value = wmi_uint64(output.Get(), L"ReturnValue").value_or(1);
  if (return_value != 0 && return_value != 4096) {
    return {false, "action_rejected_" + std::to_string(return_value)};
  }

  return wait_for_virtual_machine_state(
             services.Get(), normalized_source_id, expected_name, expected_state, 30)
             ? hyperv_action_result{true, "state_confirmed"}
             : hyperv_action_result{false, "state_confirmation_timeout"};
}

hyperv_console_result execute_hyperv_console_cycle(
    const std::string& source_id,
    const std::string& expected_name,
    std::uint16_t width,
    std::uint16_t height,
    const std::vector<hyperv_console_input>& inputs) {
  if (!is_guid(source_id) || expected_name.empty() || expected_name.size() > 255) {
    return {false, "invalid_vm_identity", {}, 0, 0, {}};
  }
  if (width < 160 || width > 1920 || height < 120 || height > 1200 ||
      inputs.size() > 64) {
    return {false, "invalid_console_contract", {}, 0, 0, {}};
  }
  auto normalized_source_id = source_id;
  std::transform(
      normalized_source_id.begin(), normalized_source_id.end(), normalized_source_id.begin(),
      [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  com_scope com;
  if (!com.initialized) return {false, "com_initialization_failed", {}, 0, 0, {}};
  const auto connection = connect_hyperv_services();
  if (!connection.value) return {false, connection.error, {}, 0, 0, {}};
  const auto lookup = find_virtual_machine(
      connection.value.Get(), normalized_source_id, expected_name);
  if (!lookup.query_succeeded) return {false, "vm_lookup_failed", {}, 0, 0, {}};
  if (lookup.identity_conflict) return {false, "vm_identity_conflict", {}, 0, 0, {}};
  if (!lookup.system) return {false, "vm_not_found", {}, 0, 0, {}};
  if (normalized_state(wmi_uint64(lookup.system.Get(), L"EnabledState").value_or(0)) !=
      "running") {
    return {false, "invalid_vm_state", {}, 0, 0, {}};
  }
  std::vector<std::string> acknowledged;
  for (const auto& input : inputs) {
    if (!apply_console_input(connection.value.Get(), normalized_source_id, input)) {
      return {false, "console_input_failed", {}, 0, 0, acknowledged};
    }
    acknowledged.push_back(input.id);
  }
  auto settings = find_realized_settings(connection.value.Get(), normalized_source_id);
  if (!settings) return {false, "console_settings_unavailable", {}, 0, 0, acknowledged};
  std::string frame_failure_code;
  auto png = capture_console_frame(
      connection.value.Get(), settings.Get(), normalized_source_id, width, height,
      frame_failure_code);
  if (png.empty()) {
    if (frame_failure_code.empty()) frame_failure_code = "console_frame_unavailable";
    return {false, frame_failure_code, {}, 0, 0, acknowledged};
  }
  return {true, "frame_captured", std::move(png), width, height, std::move(acknowledged)};
}

}  // namespace ipms::agent::windows
