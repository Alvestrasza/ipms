#include "ipms/agent/hyperv_management_settings_wmi.hpp"
#include "ipms/agent/hyperv_management_settings.hpp"

namespace ipms::agent::windows {
namespace {

namespace wmi = management_wmi;
namespace json = management_json;
using wmi::ComPtr;

bool property_type(IWbemClassObject* object, const wchar_t* property, CIMTYPE expected) {
  VARIANT value{};
  VariantInit(&value);
  CIMTYPE type{};
  const auto result = object->Get(property, 0, &value, &type, nullptr);
  VariantClear(&value);
  return SUCCEEDED(result) && type == expected;
}

std::wstring wide(const std::string& text) {
  if (text.empty()) return {};
  const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (length <= 0) return {};
  std::wstring result(static_cast<std::size_t>(length), L'\0');
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), length)) return {};
  return result;
}

bool put_text(IWbemClassObject* object, const wchar_t* property, const std::wstring& text, CIMTYPE expected = CIM_STRING) {
  if (!property_type(object, property, expected)) return false;
  VARIANT value{};
  VariantInit(&value);
  value.vt = VT_BSTR;
  value.bstrVal = SysAllocStringLen(text.data(), static_cast<UINT>(text.size()));
  const auto result = value.bstrVal ? object->Put(property, 0, &value, 0) : E_OUTOFMEMORY;
  VariantClear(&value);
  return SUCCEEDED(result);
}

bool put_array(IWbemClassObject* object, const wchar_t* property, const std::wstring& text) {
  if (!property_type(object, property, CIM_STRING | CIM_FLAG_ARRAY)) return false;
  VARIANT value{};
  VariantInit(&value);
  value.vt = VT_ARRAY | VT_BSTR;
  value.parray = SafeArrayCreateVector(VT_BSTR, 0, 1);
  BSTR item = SysAllocStringLen(text.data(), static_cast<UINT>(text.size()));
  LONG index = 0;
  auto result = value.parray && item ? SafeArrayPutElement(value.parray, &index, item) : E_OUTOFMEMORY;
  if (SUCCEEDED(result)) result = object->Put(property, 0, &value, 0);
  if (item) SysFreeString(item);
  VariantClear(&value);
  return SUCCEEDED(result);
}

bool put_boolean(IWbemClassObject* object, const wchar_t* property, bool enabled) {
  if (!property_type(object, property, CIM_BOOLEAN)) return false;
  VARIANT value{};
  VariantInit(&value);
  value.vt = VT_BOOL;
  value.boolVal = enabled ? VARIANT_TRUE : VARIANT_FALSE;
  return SUCCEEDED(object->Put(property, 0, &value, 0));
}

}  // namespace

prepared_hyperv_settings prepare_hyperv_settings(IWbemServices* services,
    const hyperv_management_command& command, wmi::deadline_type deadline) {
  prepared_hyperv_settings prepared;
  const auto error = hyperv::validate_settings_parameters(command.parameters);
  if (!error.empty()) { prepared.error = error; return prepared; }
  const auto current = wmi::read_current_configuration(services, command.target.vm_source_id, deadline);
  if (!current.error.empty()) { prepared.error = current.error; return prepared; }
  const auto& parameters = command.parameters.as<json::object>();
  const auto& section = parameters.at("section").as<std::string>();
  const auto& values = parameters.at("values").as<json::object>();
  auto* source = section == "general" ? current.settings.Get() :
      section == "processor" ? current.processor.Get() : current.memory.Get();
  ComPtr<IWbemClassObject> modified;
  if (FAILED(source->Clone(&modified)) || !modified) { prepared.error = "settings_clone_failed"; return prepared; }
  bool valid = true;
  if (section == "general") {
    if (values.contains("name")) {
      const auto name = wide(values.at("name").as<std::string>());
      valid = !name.empty() && name.size() <= 100 && put_text(modified.Get(), L"ElementName", name);
    }
    if (values.contains("notes")) valid = valid && put_array(modified.Get(), L"Notes", wide(values.at("notes").as<std::string>()));
  } else if (section == "processor") {
    valid = put_text(modified.Get(), L"VirtualQuantity", std::to_wstring(values.at("count").as<std::int64_t>()), CIM_UINT64);
  } else {
    // Change only the allowlisted requested properties on the exact local clone.
    // Offline-only properties are never assigned as part of a live patch.
    for (const auto& [key, value] : values) {
      if (key == "dynamic_enabled") valid = valid && put_boolean(modified.Get(), L"DynamicMemoryEnabled", value.as<bool>());
      else {
        const auto property = key == "startup_mib" ? L"VirtualQuantity" : key == "minimum_mib" ? L"Reservation" : L"Limit";
        valid = valid && put_text(modified.Get(), property, std::to_wstring(value.as<std::int64_t>()), CIM_UINT64);
      }
    }
  }
  if (!valid) { prepared.error = "settings_property_unsupported"; return prepared; }
  const auto encoded = wmi::object_xml(modified.Get());
  if (!encoded) { prepared.error = "settings_serialization_failed"; return prepared; }
  const auto& embedded = *encoded;
  bool complete = false;
  const auto service_rows = wmi::query(services, L"SELECT * FROM Msvm_VirtualSystemManagementService", 2, deadline, complete);
  if (!complete || service_rows.size() != 1) { prepared.error = "settings_service_unavailable"; return prepared; }
  prepared.service_path = wmi::text(service_rows[0].Get(), L"__RELPATH");
  if (!prepared.service_path.starts_with(L"Msvm_VirtualSystemManagementService.")) { prepared.error = "settings_service_unavailable"; return prepared; }
  ComPtr<IWbemClassObject> service_class, signature;
  BSTR class_name = SysAllocString(L"Msvm_VirtualSystemManagementService");
  const auto fetched = class_name ? services->GetObject(class_name, 0, nullptr, &service_class, nullptr) : E_OUTOFMEMORY;
  if (class_name) SysFreeString(class_name);
  const bool general = section == "general";
  prepared.method = general ? settings_provider_method::modify_system : settings_provider_method::modify_resource;
  const auto method = general ? L"ModifySystemSettings" : L"ModifyResourceSettings";
  if (FAILED(fetched) || !service_class || FAILED(service_class->GetMethod(method, 0, &signature, nullptr)) || !signature ||
      FAILED(signature->SpawnInstance(0, &prepared.input)) || !prepared.input) {
    prepared.error = "settings_method_unavailable"; return prepared;
  }
  // These embedded objects were encoded only from the exact local clone. The
  // operator never supplies XML, InstanceID, class, method, path, or property.
  if (!(general ? put_text(prepared.input.Get(), L"SystemSettings", embedded) :
        put_array(prepared.input.Get(), L"ResourceSettings", embedded))) prepared.error = "settings_input_invalid";
  return prepared;
}

}  // namespace ipms::agent::windows
