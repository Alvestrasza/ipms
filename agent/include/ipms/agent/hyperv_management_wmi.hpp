#pragma once

#include "ipms/agent/hyperv_management_selection.hpp"

#include <windows.h>
#include <wbemidl.h>
#include <wrl/client.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <optional>
#include <string>
#include <vector>

// Private Windows adapter utilities shared by inventory and the inspector.
// These are fixed local reads; no caller-controlled WMI expression is exposed
// through the public management contract.
namespace ipms::agent::windows::management_wmi {

using Microsoft::WRL::ComPtr;
using deadline_type = std::chrono::steady_clock::time_point;

inline std::string utf8(const std::wstring& value) {
  if (value.empty()) return {};
  const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (length <= 0) return {};
  std::string output(static_cast<std::size_t>(length), '\0');
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), output.data(), length, nullptr, nullptr)) return {};
  return output;
}

inline std::wstring text(IWbemClassObject* row, const wchar_t* property) {
  if (!row) return {};
  VARIANT value{};
  VariantInit(&value);
  std::wstring output;
  if (SUCCEEDED(row->Get(property, 0, &value, nullptr, nullptr)) &&
      value.vt == VT_BSTR && value.bstrVal && SysStringLen(value.bstrVal) <= 16'384) {
    output.assign(value.bstrVal, SysStringLen(value.bstrVal));
  }
  VariantClear(&value);
  return output;
}

inline std::optional<std::uint64_t> number(IWbemClassObject* row, const wchar_t* property) {
  if (!row) return {};
  VARIANT value{};
  VariantInit(&value);
  std::optional<std::uint64_t> output;
  if (SUCCEEDED(row->Get(property, 0, &value, nullptr, nullptr))) {
    switch (value.vt) {
      case VT_UI1: output = value.bVal; break;
      case VT_UI2: output = value.uiVal; break;
      case VT_UI4: output = value.ulVal; break;
      case VT_UI8: output = value.ullVal; break;
      case VT_I2: if (value.iVal >= 0) output = value.iVal; break;
      case VT_I4: if (value.lVal >= 0) output = value.lVal; break;
      case VT_I8: if (value.llVal >= 0) output = value.llVal; break;
      case VT_BSTR: {
        if (!value.bstrVal || SysStringLen(value.bstrVal) == 0 || SysStringLen(value.bstrVal) > 20) break;
        std::uint64_t accumulated = 0;
        bool valid = true;
        for (UINT index = 0; index < SysStringLen(value.bstrVal); ++index) {
          const auto digit = value.bstrVal[index];
          if (digit < L'0' || digit > L'9' ||
              accumulated > (UINT64_MAX - static_cast<unsigned>(digit - L'0')) / 10) {
            valid = false;
            break;
          }
          accumulated = accumulated * 10 + static_cast<unsigned>(digit - L'0');
        }
        if (valid) output = accumulated;
        break;
      }
      default: break;
    }
  }
  VariantClear(&value);
  return output;
}

inline std::optional<bool> boolean(IWbemClassObject* row, const wchar_t* property) {
  if (!row) return {};
  VARIANT value{};
  VariantInit(&value);
  std::optional<bool> output;
  if (SUCCEEDED(row->Get(property, 0, &value, nullptr, nullptr)) && value.vt == VT_BOOL) {
    output = value.boolVal != VARIANT_FALSE;
  }
  VariantClear(&value);
  return output;
}

inline std::string guid(const std::wstring& value) {
  auto candidate = utf8(value);
  if (candidate.size() == 38 && candidate.front() == '{' && candidate.back() == '}') {
    candidate = candidate.substr(1, 36);
  }
  for (auto& character : candidate) if (character >= 'A' && character <= 'F') character += 'a' - 'A';
  return hyperv::canonical_guid(candidate) ? candidate : std::string{};
}

inline std::optional<std::wstring> object_xml(IWbemClassObject* object) {
  if (!object) return {};
  ComPtr<IWbemObjectTextSrc> encoder;
  if (FAILED(CoCreateInstance(CLSID_WbemObjectTextSrc, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&encoder)))) return {};
  // Encode only instance configuration. Provider/server path metadata must not
  // alter a configuration revision or become part of an embedded write object.
  ComPtr<IWbemContext> context;
  if (FAILED(CoCreateInstance(CLSID_WbemContext, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&context)))) return {};
  VARIANT option{};
  VariantInit(&option);
  option.vt = VT_BOOL;
  option.boolVal = VARIANT_TRUE;
  if (FAILED(context->SetValue(L"ExcludeSystemProperties", 0, &option))) return {};
  option.boolVal = VARIANT_FALSE;
  if (FAILED(context->SetValue(L"IncludeQualifiers", 0, &option)) ||
      FAILED(context->SetValue(L"IncludeClassOrigin", 0, &option))) return {};
  option.vt = VT_I4;
  option.lVal = 0;
  if (FAILED(context->SetValue(L"PathLevel", 0, &option))) return {};
  BSTR output = nullptr;
  const auto result = encoder->GetText(0, object, WMI_OBJ_TEXT_WMI_DTD_2_0, context.Get(), &output);
  std::optional<std::wstring> text;
  if (SUCCEEDED(result) && output && SysStringLen(output) <= 128 * 1024) text = std::wstring(output, SysStringLen(output));
  if (output) SysFreeString(output);
  return text;
}

inline std::vector<ComPtr<IWbemClassObject>> query(
    IWbemServices* services, const std::wstring& statement, std::size_t limit,
    deadline_type deadline, bool& complete) {
  complete = false;
  std::vector<ComPtr<IWbemClassObject>> result;
  if (!services || statement.empty() || std::chrono::steady_clock::now() >= deadline) return result;
  BSTR language = SysAllocString(L"WQL");
  BSTR allocated = SysAllocString(statement.c_str());
  ComPtr<IEnumWbemClassObject> rows;
  const auto status = language && allocated ? services->ExecQuery(language, allocated,
      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &rows) : E_OUTOFMEMORY;
  if (language) SysFreeString(language);
  if (allocated) SysFreeString(allocated);
  if (FAILED(status) || !rows) return result;
  while (std::chrono::steady_clock::now() < deadline) {
    ComPtr<IWbemClassObject> row;
    ULONG returned = 0;
    const auto next = rows->Next(100, 1, row.ReleaseAndGetAddressOf(), &returned);
    if (next == WBEM_S_FALSE && returned == 0) {
      complete = true;
      return result;
    }
    if (next == WBEM_S_TIMEDOUT && returned == 0) continue;
    if (FAILED(next) || returned != 1 || !row || result.size() >= limit) return result;
    result.push_back(std::move(row));
  }
  return result;
}

inline ComPtr<IWbemClassObject> current_settings(
    IWbemServices* services, const std::string& source_id, deadline_type deadline) {
  if (!hyperv::canonical_guid(source_id)) return {};
  const std::wstring id(source_id.begin(), source_id.end());
  bool complete = false;
  auto rows = query(services,
      L"ASSOCIATORS OF {Msvm_ComputerSystem.CreationClassName=\"Msvm_ComputerSystem\",Name=\"" +
      id + L"\"} WHERE AssocClass=Msvm_SettingsDefineState ResultClass=Msvm_VirtualSystemSettingData "
      L"Role=ManagedElement ResultRole=SettingData", 8, deadline, complete);
  if (!complete) return {};
  std::vector<hyperv::settings_identity> identities;
  for (const auto& row : rows) identities.push_back({
      guid(text(row.Get(), L"VirtualSystemIdentifier")), utf8(text(row.Get(), L"VirtualSystemType"))});
  const auto selected = hyperv::unique_current_settings(identities, source_id);
  return selected ? rows[*selected] : ComPtr<IWbemClassObject>{};
}

inline ComPtr<IWbemClassObject> current_resource(
    IWbemServices* services, IWbemClassObject* settings, hyperv::resource_kind kind,
    deadline_type deadline) {
  const auto statement = hyperv::current_resource_query(text(settings, L"__RELPATH"), kind);
  bool complete = false;
  auto rows = query(services, statement, 2, deadline, complete);
  if (!complete || rows.size() != 1) return {};
  const auto expected = kind == hyperv::resource_kind::processor
      ? L"Microsoft:Hyper-V:Processor" : L"Microsoft:Hyper-V:Memory";
  if (text(rows[0].Get(), L"ResourceSubType") != expected) return {};
  return rows[0];
}

struct current_configuration {
  ComPtr<IWbemClassObject> settings;
  ComPtr<IWbemClassObject> processor;
  ComPtr<IWbemClassObject> memory;
  std::string error;
};

inline current_configuration read_current_configuration(
    IWbemServices* services, const std::string& source_id, deadline_type deadline) {
  current_configuration result;
  result.settings = current_settings(services, source_id, deadline);
  if (!result.settings) { result.error = "hyperv_settings_query_failed"; return result; }
  result.processor = current_resource(services, result.settings.Get(), hyperv::resource_kind::processor, deadline);
  if (!result.processor) { result.error = "hyperv_processor_query_failed"; return result; }
  result.memory = current_resource(services, result.settings.Get(), hyperv::resource_kind::memory, deadline);
  if (!result.memory) result.error = "hyperv_memory_query_failed";
  return result;
}

}  // namespace ipms::agent::windows::management_wmi
