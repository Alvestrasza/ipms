#include "ipms/agent/hyperv_management.hpp"
#include "ipms/agent/hyperv_management_wmi.hpp"
#include "ipms/agent/management_json.hpp"

#include <bcrypt.h>

#include <array>
#include <cstdio>
#include <limits>
#include <map>
#include <set>

namespace ipms::agent::windows {
namespace {

namespace wmi = management_wmi;
namespace json = management_json;
using wmi::ComPtr;

struct com_scope {
  bool initialized{SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))};
  ~com_scope() { if (initialized) CoUninitialize(); }
};

ComPtr<IWbemServices> connect_provider() {
  const auto security = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
      RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
  if (FAILED(security) && security != RPC_E_TOO_LATE) return {};
  ComPtr<IWbemLocator> locator;
  if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
      IID_PPV_ARGS(&locator)))) return {};
  BSTR path = SysAllocString(L"ROOT\\Virtualization\\V2");
  if (!path) return {};
  ComPtr<IWbemServices> services;
  const auto status = locator->ConnectServer(path, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
  SysFreeString(path);
  if (FAILED(status) || !services || FAILED(CoSetProxyBlanket(services.Get(),
      RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE))) return {};
  return services;
}

json::value numeric(IWbemClassObject* row, const wchar_t* property,
                    std::uint64_t maximum = static_cast<std::uint64_t>(INT64_MAX)) {
  const auto number = wmi::number(row, property);
  return number && *number <= maximum ? json::value(static_cast<std::int64_t>(*number)) : json::value{};
}

json::value boolean(IWbemClassObject* row, const wchar_t* property) {
  const auto value = wmi::boolean(row, property);
  return value ? json::value(*value) : json::value{};
}

json::value text(IWbemClassObject* row, const wchar_t* property, std::size_t maximum) {
  const auto value = wmi::utf8(wmi::text(row, property));
  return !value.empty() && value.size() <= maximum ? json::value(value) : json::value{};
}

json::value notes(IWbemClassObject* row) {
  VARIANT value{};
  VariantInit(&value);
  std::string output;
  bool valid = false;
  if (SUCCEEDED(row->Get(L"Notes", 0, &value, nullptr, nullptr))) {
    if (value.vt == VT_NULL || value.vt == VT_EMPTY) valid = true;
    if (value.vt == (VT_ARRAY | VT_BSTR) && value.parray && SafeArrayGetDim(value.parray) == 1) {
      LONG lower = 0, upper = -1;
      valid = SUCCEEDED(SafeArrayGetLBound(value.parray, 1, &lower)) &&
          SUCCEEDED(SafeArrayGetUBound(value.parray, 1, &upper)) &&
          static_cast<std::int64_t>(upper) - lower < 64;
      for (LONG index = lower; valid && index <= upper; ++index) {
        BSTR item = nullptr;
        if (FAILED(SafeArrayGetElement(value.parray, &index, &item))) { valid = false; break; }
        if (item && SysStringLen(item) > 4096) { SysFreeString(item); valid = false; break; }
        const auto entry = item ? wmi::utf8(std::wstring(item, SysStringLen(item))) : std::string{};
        if (item) SysFreeString(item);
        if (index != lower) output += '\n';
        output += entry;
        if (output.size() > 4096) valid = false;
      }
    }
  }
  VariantClear(&value);
  return valid ? json::value(output) : json::value{};
}

std::string normalized_state(std::uint64_t state) {
  switch (state) {
    case 2: return "running";
    case 3: return "stopped";
    case 4: case 32774: return "stopping";
    case 6: return "offline";
    case 9: case 32768: return "paused";
    case 10: return "starting";
    case 32769: return "suspended";
    case 32773: return "saving";
    case 32776: return "pausing";
    case 32777: return "resuming";
    default: return "unknown";
  }
}

json::value utc_timestamp(const std::wstring& value) {
  // WMI datetime includes six subsecond digits and an explicit minute offset.
  // Wildcards/unknown offsets are unavailable, not invented local/UTC time.
  if (value.size() != 25 || value[14] != L'.' || (value[21] != L'+' && value[21] != L'-')) return {};
  const auto digits = [&](std::size_t begin, std::size_t length) -> std::optional<unsigned> {
    unsigned result = 0;
    for (std::size_t index = begin; index < begin + length; ++index) {
      if (value[index] < L'0' || value[index] > L'9') return {};
      result = result * 10 + static_cast<unsigned>(value[index] - L'0');
    }
    return result;
  };
  const auto year = digits(0, 4), month = digits(4, 2), day = digits(6, 2);
  const auto hour = digits(8, 2), minute = digits(10, 2), second = digits(12, 2);
  const auto fraction = digits(15, 6), offset = digits(22, 3);
  if (!year || !month || !day || !hour || !minute || !second || !fraction || !offset) return {};
  SYSTEMTIME local{};
  local.wYear = static_cast<WORD>(*year); local.wMonth = static_cast<WORD>(*month);
  local.wDay = static_cast<WORD>(*day); local.wHour = static_cast<WORD>(*hour);
  local.wMinute = static_cast<WORD>(*minute); local.wSecond = static_cast<WORD>(*second);
  FILETIME stamp{};
  if (!SystemTimeToFileTime(&local, &stamp)) return {};
  const auto ticks = (static_cast<std::uint64_t>(stamp.dwHighDateTime) << 32) | stamp.dwLowDateTime;
  const auto adjustment = static_cast<std::uint64_t>(*offset) * 60 * 10'000'000;
  if (value[21] == L'+' && ticks < adjustment) return {};
  const auto utc = value[21] == L'+' ? ticks - adjustment : ticks + adjustment;
  FILETIME utc_file{static_cast<DWORD>(utc), static_cast<DWORD>(utc >> 32)};
  SYSTEMTIME time{};
  if (!FileTimeToSystemTime(&utc_file, &time)) return {};
  std::array<char, 40> output{};
  const auto length = std::snprintf(output.data(), output.size(),
      "%04u-%02u-%02uT%02u:%02u:%02u.%06uZ", static_cast<unsigned>(time.wYear),
      static_cast<unsigned>(time.wMonth), static_cast<unsigned>(time.wDay),
      static_cast<unsigned>(time.wHour), static_cast<unsigned>(time.wMinute),
      static_cast<unsigned>(time.wSecond), *fraction);
  return length > 0 && static_cast<std::size_t>(length) < output.size()
      ? json::value(output.data()) : json::value{};
}

std::string checkpoint_id(IWbemClassObject* row) {
  auto result = wmi::guid(wmi::text(row, L"ConfigurationID"));
  if (!result.empty()) return result;
  const auto instance_id = wmi::text(row, L"InstanceID");
  constexpr std::wstring_view prefix = L"Microsoft:";
  return instance_id.starts_with(prefix) ? wmi::guid(instance_id.substr(prefix.size())) : std::string{};
}

struct checkpoint_observation {
  json::array rows;
  bool complete{false};
};

checkpoint_observation read_checkpoints(IWbemServices* services,
    IWbemClassObject* current, const std::string& vm_id, wmi::deadline_type deadline) {
  bool complete = false;
  const std::wstring id(vm_id.begin(), vm_id.end());
  auto rows = wmi::query(services,
      L"SELECT * FROM Msvm_VirtualSystemSettingData WHERE VirtualSystemIdentifier = '" + id + L"'",
      257, deadline, complete);
  if (!complete) return {};
  struct checkpoint_row { ComPtr<IWbemClassObject> row; std::string id; std::string type; };
  std::vector<checkpoint_row> checkpoints;
  std::map<std::wstring, std::string> paths;
  std::set<std::string> identifiers;
  for (const auto& row : rows) {
    if (wmi::guid(wmi::text(row.Get(), L"VirtualSystemIdentifier")) != vm_id) return {};
    const auto type = wmi::text(row.Get(), L"VirtualSystemType");
    if (!type.starts_with(L"Microsoft:Hyper-V:Snapshot:")) continue;
    const auto checkpoint = checkpoint_id(row.Get());
    const auto name = wmi::utf8(wmi::text(row.Get(), L"ElementName"));
    if (checkpoint.empty() || name.empty() || name.size() > 256 || !identifiers.insert(checkpoint).second ||
        checkpoints.size() >= 256) return {};
    const auto relative = wmi::text(row.Get(), L"__RELPATH");
    const auto absolute = wmi::text(row.Get(), L"__PATH");
    if (!relative.empty()) paths[relative] = checkpoint;
    if (!absolute.empty()) paths[absolute] = checkpoint;
    checkpoints.push_back({row, checkpoint, type == L"Microsoft:Hyper-V:Snapshot:Recovery" ? "recovery" : "unknown"});
  }
  std::sort(checkpoints.begin(), checkpoints.end(), [](const auto& left, const auto& right) { return left.id < right.id; });
  const auto current_parent_path = wmi::text(current, L"Parent");
  const auto current_parent = paths.find(current_parent_path);
  if (!current_parent_path.empty() && current_parent == paths.end()) return {};
  checkpoint_observation result;
  for (const auto& checkpoint : checkpoints) {
    const auto parent_path = wmi::text(checkpoint.row.Get(), L"Parent");
    const auto parent = paths.find(parent_path);
    if (!parent_path.empty() && parent == paths.end()) return {};
    result.rows.emplace_back(json::object{
        {"id", checkpoint.id},
        {"name", wmi::utf8(wmi::text(checkpoint.row.Get(), L"ElementName"))},
        {"created_at", utc_timestamp(wmi::text(checkpoint.row.Get(), L"CreationTime"))},
        {"parent_id", parent != paths.end() ? json::value(parent->second) : json::value{}},
        {"type", checkpoint.type},
        {"is_current", current_parent != paths.end() && current_parent->second == checkpoint.id},
        {"can_apply", wmi::text(checkpoint.row.Get(), L"VirtualSystemType") == L"Microsoft:Hyper-V:Snapshot:Realized"},
        {"can_delete", wmi::text(checkpoint.row.Get(), L"VirtualSystemType") == L"Microsoft:Hyper-V:Snapshot:Realized"}});
  }
  // A corrupt or incomplete tree is unsuitable for affected-descendant
  // confirmations. Do not emit root nodes by silently dropping parent edges.
  std::map<std::string, std::string> parents;
  for (const auto& row : result.rows) {
    const auto& fields = row.as<json::object>();
    const auto* parent = fields.at("parent_id").get_if<std::string>();
    parents.emplace(fields.at("id").as<std::string>(), parent ? *parent : "");
  }
  for (const auto& [checkpoint_key, _] : parents) {
    std::set<std::string> visited;
    auto cursor = checkpoint_key;
    while (!cursor.empty()) {
      const auto parent = parents.find(cursor);
      if (parent == parents.end() || !visited.insert(cursor).second) return {};
      cursor = parent->second;
    }
  }
  result.complete = true;
  try {
    // Reserve room for settings and the full transport envelope. An oversized
    // section is unavailable rather than a silently truncated checkpoint tree.
    (void)json::serialize(result.rows, json::limits{.document_bytes = 36 * 1024});
  } catch (const std::exception&) { return {}; }
  return result;
}

json::array qualifier_strings(IWbemQualifierSet* qualifiers, const wchar_t* property) {
  json::array output;
  if (!qualifiers) return output;
  VARIANT value{};
  VariantInit(&value);
  if (SUCCEEDED(qualifiers->Get(property, 0, &value, nullptr)) &&
      value.vt == (VT_ARRAY | VT_BSTR) && value.parray && SafeArrayGetDim(value.parray) == 1) {
    LONG lower = 0, upper = -1;
    if (SUCCEEDED(SafeArrayGetLBound(value.parray, 1, &lower)) &&
        SUCCEEDED(SafeArrayGetUBound(value.parray, 1, &upper)) &&
        static_cast<std::int64_t>(upper) - lower < 64) {
      for (LONG index = lower; index <= upper; ++index) {
        BSTR item = nullptr;
        if (FAILED(SafeArrayGetElement(value.parray, &index, &item)) || !item) { output.clear(); break; }
        const auto entry = SysStringLen(item) <= 256
            ? wmi::utf8(std::wstring(item, SysStringLen(item))) : std::string{};
        SysFreeString(item);
        if (entry.empty() || entry.size() > 256) { output.clear(); break; }
        output.emplace_back(entry);
      }
    }
  }
  VariantClear(&value);
  return output;
}

json::value property_schema(IWbemClassObject* object, const wchar_t* name) {
  if (!object) return {};
  VARIANT value{};
  VariantInit(&value);
  CIMTYPE type{};
  const auto found = object->Get(name, 0, &value, &type, nullptr);
  VariantClear(&value);
  if (FAILED(found)) return {};
  ComPtr<IWbemQualifierSet> qualifiers;
  object->GetPropertyQualifierSet(name, &qualifiers);
  return json::object{{"cim_type", static_cast<std::int64_t>(type)},
      {"value_map", qualifier_strings(qualifiers.Get(), L"ValueMap")},
      {"values", qualifier_strings(qualifiers.Get(), L"Values")}};
}

std::string read_provider_schema(IWbemServices* services, wmi::deadline_type deadline) {
  if (std::chrono::steady_clock::now() >= deadline) return {};
  ComPtr<IWbemClassObject> snapshot_class, vm_settings_class, management_class;
  BSTR snapshot_name = SysAllocString(L"Msvm_VirtualSystemSnapshotService");
  BSTR settings_name = SysAllocString(L"Msvm_VirtualSystemSettingData");
  if (snapshot_name) services->GetObject(snapshot_name, 0, nullptr, &snapshot_class, nullptr);
  if (settings_name) services->GetObject(settings_name, 0, nullptr, &vm_settings_class, nullptr);
  if (snapshot_name) SysFreeString(snapshot_name);
  if (settings_name) SysFreeString(settings_name);
  BSTR management_name = SysAllocString(L"Msvm_VirtualSystemManagementService");
  if (management_name) services->GetObject(management_name, 0, nullptr, &management_class, nullptr);
  if (management_name) SysFreeString(management_name);
  json::object methods;
  if (snapshot_class) {
    for (const auto method : {L"CreateSnapshot", L"ApplySnapshot", L"DestroySnapshot"}) {
      if (std::chrono::steady_clock::now() >= deadline) return {};
      ComPtr<IWbemClassObject> input, output;
      const auto found = snapshot_class->GetMethod(method, 0, &input, &output);
      json::object fields;
      const std::wstring method_name(method);
      if (method_name == L"CreateSnapshot") {
        for (const auto parameter : {L"AffectedSystem", L"SnapshotSettings", L"SnapshotType"}) {
          fields.emplace(wmi::utf8(parameter), property_schema(input.Get(), parameter));
        }
      } else {
        const auto parameter = method_name == L"ApplySnapshot" ? L"Snapshot" : L"AffectedSnapshot";
        fields.emplace(wmi::utf8(parameter), property_schema(input.Get(), parameter));
      }
      methods.emplace(wmi::utf8(method_name), json::object{
          {"present", SUCCEEDED(found)}, {"input", std::move(fields)},
          {"job", property_schema(output.Get(), L"Job")}});
    }
  }
  json::object settings_methods;
  if (management_class) {
    for (const auto method : {L"ModifySystemSettings", L"ModifyResourceSettings"}) {
      if (std::chrono::steady_clock::now() >= deadline) return {};
      ComPtr<IWbemClassObject> input, output;
      const auto found = management_class->GetMethod(method, 0, &input, &output);
      const auto parameter = std::wstring_view(method) == L"ModifySystemSettings" ? L"SystemSettings" : L"ResourceSettings";
      settings_methods.emplace(wmi::utf8(method), json::object{{"present", SUCCEEDED(found)},
          {"input", property_schema(input.Get(), parameter)}, {"job", property_schema(output.Get(), L"Job")}});
    }
  }
  try {
    return json::serialize(json::object{{"schema_version", 1},
        {"mutation_behavior_verified", false}, {"snapshot_methods", std::move(methods)},
        {"settings_methods", std::move(settings_methods)},
        {"user_snapshot_type", property_schema(vm_settings_class.Get(), L"UserSnapshotType")}},
        json::limits{.document_bytes = 16 * 1024});
  } catch (const std::exception&) { return {}; }
}

bool supports_settings_methods(const json::value& schema, const wmi::current_configuration& current) {
  try {
    const auto& methods = schema.as<json::object>().at("settings_methods").as<json::object>();
    for (const auto name : {"ModifySystemSettings", "ModifyResourceSettings"}) {
      const auto& method = methods.at(name).as<json::object>();
      const auto expected = std::string_view(name) == "ModifySystemSettings" ? CIM_STRING : CIM_STRING | CIM_FLAG_ARRAY;
      if (!method.at("present").as<bool>() ||
          method.at("input").as<json::object>().at("cim_type").as<std::int64_t>() != expected ||
          method.at("job").as<json::object>().at("cim_type").as<std::int64_t>() != CIM_REFERENCE) return false;
    }
    const auto property = [](IWbemClassObject* object, const wchar_t* name, CIMTYPE expected) {
      VARIANT value{};
      VariantInit(&value);
      CIMTYPE type{};
      const auto result = object->Get(name, 0, &value, &type, nullptr);
      VariantClear(&value);
      return SUCCEEDED(result) && type == expected;
    };
    return property(current.settings.Get(), L"ElementName", CIM_STRING) &&
        property(current.settings.Get(), L"Notes", CIM_STRING | CIM_FLAG_ARRAY) &&
        property(current.processor.Get(), L"VirtualQuantity", CIM_UINT64) &&
        property(current.memory.Get(), L"VirtualQuantity", CIM_UINT64) &&
        property(current.memory.Get(), L"Reservation", CIM_UINT64) &&
        property(current.memory.Get(), L"Limit", CIM_UINT64) &&
        property(current.memory.Get(), L"DynamicMemoryEnabled", CIM_BOOLEAN);
  } catch (const std::exception&) { return false; }
}

bool supports_snapshot_method(const json::value& schema, const std::string& method) {
  try {
    const auto& method_schema = schema.as<json::object>().at("snapshot_methods").as<json::object>().at(method).as<json::object>();
    if (!method_schema.at("present").as<bool>() ||
        method_schema.at("job").as<json::object>().at("cim_type").as<std::int64_t>() != CIM_REFERENCE) return false;
    const auto& input = method_schema.at("input").as<json::object>();
    if (method != "CreateSnapshot") {
      const auto key = method == "ApplySnapshot" ? "Snapshot" : "AffectedSnapshot";
      return input.at(key).as<json::object>().at("cim_type").as<std::int64_t>() == CIM_REFERENCE;
    }
    if (input.at("AffectedSystem").as<json::object>().at("cim_type").as<std::int64_t>() != CIM_REFERENCE ||
        input.at("SnapshotSettings").as<json::object>().at("cim_type").as<std::int64_t>() != CIM_STRING ||
        input.at("SnapshotType").as<json::object>().at("cim_type").as<std::int64_t>() != CIM_UINT16) return false;
    // Explicit host-provider support for the documented full snapshot value.
    // Never guess a vendor value or map disk snapshots to production mode.
    const auto& values = input.at("SnapshotType").as<json::object>().at("value_map").as<json::array>();
    return std::any_of(values.begin(), values.end(), [](const auto& value) {
      const auto* text_value = value.template get_if<std::string>();
      return text_value && *text_value == "2";
    });
  } catch (const std::exception&) { return false; }
}

std::string sha256(const std::string& input) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::array<UCHAR, 32> digest{};
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return {};
  DWORD object_size = 0, copied = 0;
  const auto property = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
      reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &copied, 0);
  std::vector<UCHAR> storage;
  if (property >= 0 && object_size <= 16'384) storage.resize(object_size);
  bool valid = !storage.empty() && BCryptCreateHash(algorithm, &hash,
      storage.data(), object_size, nullptr, 0, 0) >= 0;
  if (valid) valid = BCryptHashData(hash,
      reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())), static_cast<ULONG>(input.size()), 0) >= 0 &&
      BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!valid) return {};
  std::string output;
  constexpr char digits[] = "0123456789abcdef";
  for (const auto byte : digest) { output.push_back(digits[byte >> 4]); output.push_back(digits[byte & 15]); }
  return output;
}

}  // namespace

hyperv_management_inspection inspect_hyperv_virtual_machine(const hyperv_management_target& target) {
  if (!hyperv::canonical_guid(target.vm_source_id) || target.expected_name.empty() ||
      target.expected_name.size() > 256) return {false, "invalid_vm_identity", {}};
  for (const unsigned char character : target.expected_name) if (character < 0x20 || character == 0x7f) {
    return {false, "invalid_vm_identity", {}};
  }
  com_scope com;
  if (!com.initialized) return {false, "com_initialization_failed", {}};
  const auto services = connect_provider();
  if (!services) return {false, "hyperv_provider_unavailable", {}};
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  bool complete = false;
  const std::wstring id(target.vm_source_id.begin(), target.vm_source_id.end());
  const auto systems = wmi::query(services.Get(),
      L"SELECT Name, ElementName, EnabledState FROM Msvm_ComputerSystem WHERE Name = '" + id + L"'", 2, deadline, complete);
  if (!complete || systems.size() != 1) return {false, "vm_lookup_failed", {}};
  auto* system = systems[0].Get();
  if (wmi::guid(wmi::text(system, L"Name")) != target.vm_source_id ||
      wmi::utf8(wmi::text(system, L"ElementName")) != target.expected_name) return {false, "vm_identity_conflict", {}};
  const auto current = wmi::read_current_configuration(services.Get(), target.vm_source_id, deadline);
  if (!current.error.empty()) return {false, current.error, {}};
  auto* settings = current.settings.Get();
  auto* processor = current.processor.Get();
  auto* memory = current.memory.Get();
  auto checkpoints = read_checkpoints(services.Get(), settings, target.vm_source_id, deadline);
  const auto subtype = wmi::text(settings, L"VirtualSystemSubType");
  const auto policy = wmi::number(settings, L"UserSnapshotType");
  const auto state = normalized_state(wmi::number(system, L"EnabledState").value_or(0));
  const auto provider_schema = read_provider_schema(services.Get(), deadline);
  json::value schema;
  try { if (!provider_schema.empty()) schema = json::parse(provider_schema); }
  catch (const std::exception&) {}
  const bool stable_state = state == "running" || state == "stopped";
  const bool create_supported = checkpoints.complete && stable_state && policy && *policy == 5 &&
      supports_snapshot_method(schema, "CreateSnapshot");
  const bool delete_supported = checkpoints.complete && stable_state && supports_snapshot_method(schema, "DestroySnapshot");
  const bool apply_supported = checkpoints.complete && state == "stopped" && supports_snapshot_method(schema, "ApplySnapshot");
  const bool settings_supported = state == "stopped" && supports_settings_methods(schema, current);
  for (auto& checkpoint : checkpoints.rows) {
    auto& fields = checkpoint.as<json::object>();
    fields.at("can_delete") = fields.at("can_delete").as<bool>() && delete_supported;
    fields.at("can_apply") = fields.at("can_apply").as<bool>() && apply_supported;
  }
  json::object document{
      {"schema_version", 1}, {"vm_source_id", target.vm_source_id}, {"vm_name", target.expected_name},
      {"state", state},
      {"settings", json::object{
          {"name", target.expected_name}, {"notes", notes(settings)},
          {"configuration_version", text(settings, L"Version", 64)},
          {"generation", subtype == L"Microsoft:Hyper-V:SubType:1" ? json::value(1) :
              subtype == L"Microsoft:Hyper-V:SubType:2" ? json::value(2) : json::value{}},
          {"processor", json::object{
              {"count", numeric(processor, L"VirtualQuantity", 2048)},
              {"reservation_milli_percent", numeric(processor, L"Reservation", 100'000)},
              {"limit_milli_percent", numeric(processor, L"Limit", 100'000)},
              {"weight", numeric(processor, L"Weight", 10'000)},
              {"compatibility_for_migration", boolean(processor, L"LimitProcessorFeatures")}}},
          {"memory", json::object{
              {"startup_mib", numeric(memory, L"VirtualQuantity", 1ULL << 40)},
              {"minimum_mib", numeric(memory, L"Reservation", 1ULL << 40)},
              {"maximum_mib", numeric(memory, L"Limit", 1ULL << 40)},
              {"dynamic_enabled", boolean(memory, L"DynamicMemoryEnabled")},
              {"buffer_percent", numeric(memory, L"TargetMemoryBuffer", 2000)},
              {"weight", numeric(memory, L"Weight", 10'000)}}},
          {"automatic_start_action", numeric(settings, L"AutomaticStartupAction", 4)},
          {"automatic_start_delay", text(settings, L"AutomaticStartupActionDelay", 32)},
          {"automatic_stop_action", numeric(settings, L"AutomaticShutdownAction", 4)},
          {"checkpoint_policy", policy && *policy >= 2 && *policy <= 5 ? json::value(*policy) : json::value{}}}},
      {"checkpoints", checkpoints.rows},
      {"devices", json::object{{"network_adapters", json::array{}}, {"storage", json::array{}}}},
      {"collection_status", json::object{{"settings", "collected"},
          {"checkpoints", checkpoints.complete ? "collected" : "unavailable"}, {"devices", "not-reported"}}},
      {"capabilities", json::object{{"inspect", true}, {"checkpoint_create", create_supported},
          {"checkpoint_delete", delete_supported}, {"checkpoint_apply", apply_supported}, {"settings_update", settings_supported}}}};
  try {
    const json::limits limits{.document_bytes = 46 * 1024};
    std::string revision_material = json::serialize(document, limits);
    // A later edit clones a complete local provider object. Bind the revision
    // to every copied property, including fields not displayed by this UI, so
    // external changes to those fields cannot silently pass the final check.
    // The encoded native objects remain local and are never sent to the portal.
    for (auto* object : {settings, processor, memory}) {
      const auto encoded = wmi::object_xml(object);
      if (!encoded) return {false, "inspection_revision_failed", {}};
      const auto serialized = wmi::utf8(*encoded);
      if (serialized.empty()) return {false, "inspection_revision_failed", {}};
      revision_material += std::to_string(serialized.size()) + ":" + serialized;
    }
    const auto revision = sha256(revision_material);
    if (revision.empty()) return {false, "inspection_revision_failed", {}};
    document.emplace("revision", revision);
    return {true, "inspection_collected", json::serialize(document, limits),
        provider_schema};
  } catch (const std::exception&) {
    return {false, "inspection_payload_invalid", {}};
  }
}

}  // namespace ipms::agent::windows
