#include "ipms/agent/hyperv_management.hpp"
#include "ipms/agent/hyperv_management_guards.hpp"
#include "ipms/agent/hyperv_management_settings_wmi.hpp"
#include "ipms/agent/hyperv_management_wmi.hpp"

#include <thread>

namespace ipms::agent::windows {
namespace {

namespace wmi = management_wmi;
namespace json = management_json;
namespace journal = hyperv_management_journal;
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
  if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator)))) return {};
  BSTR path = SysAllocString(L"ROOT\\Virtualization\\V2");
  if (!path) return {};
  ComPtr<IWbemServices> services;
  const auto result = locator->ConnectServer(path, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
  SysFreeString(path);
  if (FAILED(result) || !services || FAILED(CoSetProxyBlanket(services.Get(), RPC_C_AUTHN_WINNT,
      RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE))) return {};
  return services;
}

hyperv_management_progress failure(const std::string& code) {
  return {"failed", "preflight", code, {}, {}, {}};
}

hyperv_management_progress uncertain(const std::string& code, const std::string& job = {}) {
  return {"requires_reconciliation", "requires_reconciliation", code, {}, job, {}};
}

bool put_string(IWbemClassObject* input, const wchar_t* property, const std::wstring& text) {
  VARIANT value{};
  VariantInit(&value);
  value.vt = VT_BSTR;
  value.bstrVal = SysAllocStringLen(text.data(), static_cast<UINT>(text.size()));
  const auto status = value.bstrVal ? input->Put(property, 0, &value, 0) : E_OUTOFMEMORY;
  VariantClear(&value);
  return SUCCEEDED(status);
}

std::string snapshot_id(IWbemClassObject* row) {
  auto id = wmi::guid(wmi::text(row, L"ConfigurationID"));
  if (!id.empty()) return id;
  const auto instance = wmi::text(row, L"InstanceID");
  return instance.starts_with(L"Microsoft:") ? wmi::guid(instance.substr(10)) : std::string{};
}

ComPtr<IWbemClassObject> find_checkpoint(IWbemServices* services,
    const hyperv_management_target& target, const std::string& checkpoint_id, wmi::deadline_type deadline) {
  if (!hyperv::canonical_guid(checkpoint_id)) return {};
  const std::wstring vm_id(target.vm_source_id.begin(), target.vm_source_id.end());
  bool complete = false;
  auto rows = wmi::query(services,
      L"SELECT * FROM Msvm_VirtualSystemSettingData WHERE VirtualSystemIdentifier = '" + vm_id + L"'", 257, deadline, complete);
  if (!complete) return {};
  ComPtr<IWbemClassObject> selected;
  for (const auto& row : rows) {
    if (wmi::guid(wmi::text(row.Get(), L"VirtualSystemIdentifier")) != target.vm_source_id) return {};
    if (snapshot_id(row.Get()) != checkpoint_id) continue;
    if (selected || wmi::text(row.Get(), L"VirtualSystemType") != L"Microsoft:Hyper-V:Snapshot:Realized") return {};
    selected = row;
  }
  return selected;
}

std::string local_job_reference(const std::wstring& provider_reference) {
  constexpr std::wstring_view prefix = L"Msvm_ConcreteJob.InstanceID=\"";
  const auto begin = provider_reference.find(prefix);
  if (begin == std::wstring::npos || provider_reference.size() > 2048) return {};
  const auto relative = wmi::utf8(provider_reference.substr(begin));
  return journal::local_provider_job_reference(relative) ? relative : std::string{};
}

ComPtr<IWbemClassObject> get_local_job(IWbemServices* services,
    const std::string& relative, wmi::deadline_type deadline) {
  constexpr std::string_view prefix = "Msvm_ConcreteJob.InstanceID=\"";
  if (!relative.starts_with(prefix) || !journal::local_provider_job_reference(relative)) return {};
  const auto key = relative.substr(prefix.size(), relative.size() - prefix.size() - 1);
  const std::wstring wide_key(key.begin(), key.end());
  bool complete = false;
  auto jobs = wmi::query(services, L"SELECT * FROM Msvm_ConcreteJob WHERE InstanceID = '" + wide_key + L"'", 2, deadline, complete);
  if (!complete || jobs.size() != 1 || wmi::utf8(wmi::text(jobs[0].Get(), L"__RELPATH")) != relative) return {};
  return jobs[0];
}

struct job_ownership {
  bool confirmed{false};
  std::vector<std::string> affected_checkpoints;
};

bool has_create_effect(IWbemClassObject* association) {
  VARIANT value{};
  VariantInit(&value);
  bool found = false;
  if (SUCCEEDED(association->Get(L"ElementEffects", 0, &value, nullptr, nullptr)) &&
      (value.vt == (VT_ARRAY | VT_I4) || value.vt == (VT_ARRAY | VT_UI2) || value.vt == (VT_ARRAY | VT_UI4)) &&
      value.parray && SafeArrayGetDim(value.parray) == 1) {
    LONG lower = 0, upper = -1;
    if (SUCCEEDED(SafeArrayGetLBound(value.parray, 1, &lower)) &&
        SUCCEEDED(SafeArrayGetUBound(value.parray, 1, &upper)) &&
        static_cast<std::int64_t>(upper) - lower < 64) {
      for (LONG index = lower; index <= upper; ++index) {
        if (value.vt == (VT_ARRAY | VT_UI2)) {
          USHORT effect{};
          if (SUCCEEDED(SafeArrayGetElement(value.parray, &index, &effect)) && effect == 5) found = true;
        } else {
          ULONG effect{};
          if (SUCCEEDED(SafeArrayGetElement(value.parray, &index, &effect)) && effect == 5) found = true;
        }
      }
    }
  }
  VariantClear(&value);
  return found;
}

job_ownership verify_job_ownership(IWbemServices* services, const std::string& relative,
    const hyperv_management_target& target, wmi::deadline_type deadline) {
  if (!journal::local_provider_job_reference(relative)) return {};
  const std::wstring path(relative.begin(), relative.end());
  job_ownership result;
  bool references_complete = false;
  const auto references = wmi::query(services, L"REFERENCES OF {" + path +
      L"} WHERE ResultClass=Msvm_AffectedJobElement Role=AffectingElement", 258, deadline, references_complete);
  if (!references_complete) return {};
  std::set<std::wstring> created_objects;
  for (const auto& association : references) {
    if (has_create_effect(association.Get())) created_objects.insert(wmi::text(association.Get(), L"AffectedElement"));
  }
  for (const auto class_name : {L"Msvm_ComputerSystem", L"Msvm_VirtualSystemSettingData",
      L"Msvm_ProcessorSettingData", L"Msvm_MemorySettingData"}) {
    bool complete = false;
    auto rows = wmi::query(services, L"ASSOCIATORS OF {" + path +
        L"} WHERE AssocClass=Msvm_AffectedJobElement ResultClass=" + class_name +
        L" Role=AffectingElement ResultRole=AffectedElement", 258, deadline, complete);
    if (!complete) return {};
    const bool system = std::wstring_view(class_name) == L"Msvm_ComputerSystem";
    const bool resource = std::wstring_view(class_name) == L"Msvm_ProcessorSettingData" ||
        std::wstring_view(class_name) == L"Msvm_MemorySettingData";
    for (const auto& row : rows) {
      if (resource) {
        const auto resource_path = wmi::text(row.Get(), L"__RELPATH");
        if (!resource_path.starts_with(std::wstring(class_name) + L".InstanceID=") || resource_path.size() > 512) return {};
        const auto owners = wmi::query(services, L"ASSOCIATORS OF {" + resource_path +
            L"} WHERE AssocClass=Msvm_VirtualSystemSettingDataComponent ResultClass=Msvm_VirtualSystemSettingData "
            L"Role=PartComponent ResultRole=GroupComponent", 4, deadline, complete);
        if (!complete || owners.size() != 1 ||
            wmi::guid(wmi::text(owners[0].Get(), L"VirtualSystemIdentifier")) != target.vm_source_id ||
            wmi::text(owners[0].Get(), L"VirtualSystemType") != L"Microsoft:Hyper-V:System:Realized") return {};
        result.confirmed = true;
        continue;
      }
      const auto vm_id = wmi::guid(wmi::text(row.Get(), system ? L"Name" : L"VirtualSystemIdentifier"));
      if (vm_id.empty()) continue;
      if (vm_id != target.vm_source_id) return {};
      result.confirmed = true;
      if (!system && wmi::text(row.Get(), L"VirtualSystemType") == L"Microsoft:Hyper-V:Snapshot:Realized") {
        const auto id = snapshot_id(row.Get());
        if (!id.empty() && (created_objects.contains(wmi::text(row.Get(), L"__PATH")) ||
            created_objects.contains(wmi::text(row.Get(), L"__RELPATH")))) result.affected_checkpoints.push_back(id);
      }
    }
  }
  return result;
}

hyperv_management_progress completed(const hyperv_management_command& command,
    const std::vector<std::string>& created_ids, const std::string& local_job = {}) {
  const auto inspection = inspect_hyperv_virtual_machine(hyperv::settings_result_target(command));
  if (!inspection.succeeded) return uncertain("operation_completed_inspection_unavailable", local_job);
  try {
    const auto snapshot = json::parse(inspection.document_json);
    const auto& document = snapshot.as<json::object>();
    if (command.operation != journal::operation::settings_update &&
        document.at("collection_status").as<json::object>().at("checkpoints").as<std::string>() != "collected") {
      return uncertain("operation_completed_checkpoints_unavailable", local_job);
    }
    const auto& checkpoints = document.at("checkpoints").as<json::array>();
    bool verified = false;
    if (command.operation == journal::operation::settings_update) {
      verified = hyperv::settings_postcondition(command, snapshot);
    } else if (command.operation == journal::operation::checkpoint_create) {
      for (const auto& row : checkpoints) {
        const auto& id = row.as<json::object>().at("id").as<std::string>();
        if (std::find(created_ids.begin(), created_ids.end(), id) != created_ids.end()) verified = true;
      }
    } else {
      const auto& checkpoint_id = command.parameters.as<json::object>().at("checkpoint_id").as<std::string>();
      const auto selected = std::find_if(checkpoints.begin(), checkpoints.end(), [&](const auto& row) {
        return row.template as<json::object>().at("id").template as<std::string>() == checkpoint_id;
      });
      if (command.operation == journal::operation::checkpoint_delete) verified = selected == checkpoints.end();
      if (command.operation == journal::operation::checkpoint_apply) {
        verified = selected != checkpoints.end() && selected->as<json::object>().at("is_current").as<bool>();
      }
    }
    if (!verified) return uncertain("operation_postcondition_unconfirmed", local_job);
    return {"succeeded", "completed", "operation_confirmed", static_cast<std::uint16_t>(100), local_job, inspection.document_json};
  } catch (const std::exception&) { return uncertain("operation_postcondition_invalid", local_job); }
}

}  // namespace

hyperv_management_progress execute_hyperv_management(const hyperv_management_command& command,
    const std::function<bool()>& before_invoke, const std::function<bool(const std::string&)>& on_job) {
  if (!before_invoke || !on_job) return failure("execution_journal_required");
  const auto inspection = inspect_hyperv_virtual_machine(command.target);
  if (!inspection.succeeded) return failure(inspection.result_code);
  try {
    const auto error = hyperv::validate_management_command(command, json::parse(inspection.document_json));
    if (!error.empty()) return failure(error);
  } catch (const std::exception&) { return failure("invalid_management_command"); }
  com_scope com;
  if (!com.initialized) return failure("com_initialization_failed");
  const auto services = connect_provider();
  if (!services) return failure("hyperv_provider_unavailable");
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  bool complete = false;
  std::wstring service_path;
  const wchar_t* method = nullptr;
  ComPtr<IWbemClassObject> input;
  const std::wstring vm_id(command.target.vm_source_id.begin(), command.target.vm_source_id.end());
  if (command.operation == journal::operation::settings_update) {
    const auto prepared = prepare_hyperv_settings(services.Get(), command, deadline);
    if (!prepared.error.empty()) return failure(prepared.error);
    service_path = prepared.service_path;
    method = prepared.method == settings_provider_method::modify_system ? L"ModifySystemSettings" : L"ModifyResourceSettings";
    input = prepared.input;
  } else {
  auto service_rows = wmi::query(services.Get(), L"SELECT * FROM Msvm_VirtualSystemSnapshotService", 2, deadline, complete);
  if (!complete || service_rows.size() != 1) return failure("snapshot_service_unavailable");
  service_path = wmi::text(service_rows[0].Get(), L"__RELPATH");
  if (!service_path.starts_with(L"Msvm_VirtualSystemSnapshotService.")) return failure("snapshot_service_unavailable");
  method = command.operation == journal::operation::checkpoint_create ? L"CreateSnapshot" :
      command.operation == journal::operation::checkpoint_delete ? L"DestroySnapshot" : L"ApplySnapshot";
  ComPtr<IWbemClassObject> service_class, signature;
  BSTR class_name = SysAllocString(L"Msvm_VirtualSystemSnapshotService");
  const auto class_status = class_name ? services->GetObject(class_name, 0, nullptr, &service_class, nullptr) : E_OUTOFMEMORY;
  if (class_name) SysFreeString(class_name);
  if (FAILED(class_status) || !service_class ||
      FAILED(service_class->GetMethod(method, 0, &signature, nullptr)) || !signature ||
      FAILED(signature->SpawnInstance(0, &input)) || !input) return failure("snapshot_method_unavailable");
  auto systems = wmi::query(services.Get(),
      L"SELECT Name, ElementName, EnabledState FROM Msvm_ComputerSystem WHERE Name = '" + vm_id + L"'", 2, deadline, complete);
  if (!complete || systems.size() != 1 || wmi::utf8(wmi::text(systems[0].Get(), L"ElementName")) != command.target.expected_name ||
      wmi::guid(wmi::text(systems[0].Get(), L"Name")) != command.target.vm_source_id) return failure("vm_identity_conflict");
  const auto state = wmi::number(systems[0].Get(), L"EnabledState").value_or(0);
  if ((state != 2 && state != 3) || (command.operation == journal::operation::checkpoint_apply && state != 3)) return failure("invalid_vm_state");
  if (command.operation == journal::operation::checkpoint_create) {
    const auto settings = wmi::current_settings(services.Get(), command.target.vm_source_id, deadline);
    if (!settings || wmi::number(settings.Get(), L"UserSnapshotType") != 5) return failure("checkpoint_policy_unsupported");
    if (!put_string(input.Get(), L"AffectedSystem", wmi::text(systems[0].Get(), L"__RELPATH")) ||
        !put_string(input.Get(), L"SnapshotSettings", L"")) return failure("snapshot_input_invalid");
    VARIANT type{};
    VariantInit(&type);
    type.vt = VT_I4; type.lVal = 2;
    const auto put = input->Put(L"SnapshotType", 0, &type, 0);
    VariantClear(&type);
    if (FAILED(put)) return failure("snapshot_input_invalid");
  } else {
    const auto& id = command.parameters.as<json::object>().at("checkpoint_id").as<std::string>();
    const auto checkpoint = find_checkpoint(services.Get(), command.target, id, deadline);
    if (!checkpoint || !put_string(input.Get(), command.operation == journal::operation::checkpoint_delete ? L"AffectedSnapshot" : L"Snapshot",
        wmi::text(checkpoint.Get(), L"__RELPATH"))) return failure("management_checkpoint_not_found");
  }
  }
  // Repeat the complete revision check after method-input construction. The
  // callback immediately below is the final lease/journal gate. External MMC
  // writers remain outside our lock; WMI itself has no configuration CAS API.
  const auto fresh = inspect_hyperv_virtual_machine(command.target);
  if (!fresh.succeeded) return failure(fresh.result_code);
  const auto error = hyperv::validate_management_command(command, json::parse(fresh.document_json));
  if (!error.empty()) return failure(error);
  if (!before_invoke()) return failure("execution_authority_unavailable");
  BSTR path = SysAllocString(service_path.c_str());
  BSTR method_name = SysAllocString(method);
  ComPtr<IWbemCallResult> call;
  const auto invoked = path && method_name ? services->ExecMethod(path, method_name,
      WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, input.Get(), nullptr, &call) : E_OUTOFMEMORY;
  if (path) SysFreeString(path);
  if (method_name) SysFreeString(method_name);
  if (FAILED(invoked) || !call) return uncertain("provider_acceptance_unknown");
  const auto acceptance_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  HRESULT completion = WBEM_S_TIMEDOUT;
  LONG method_status = 0;
  while (std::chrono::steady_clock::now() < acceptance_deadline) {
    completion = call->GetCallStatus(50, &method_status);
    if (completion != WBEM_S_TIMEDOUT) break;
  }
  if (completion == WBEM_S_TIMEDOUT || FAILED(completion) || FAILED(method_status)) return uncertain("provider_acceptance_unknown");
  ComPtr<IWbemClassObject> output;
  if (FAILED(call->GetResultObject(0, &output)) || !output) return uncertain("provider_acceptance_unknown");
  const auto result = wmi::number(output.Get(), L"ReturnValue");
  if (!result) return uncertain("provider_acceptance_unknown");
  if (*result == 4096) {
    const auto job = local_job_reference(wmi::text(output.Get(), L"Job"));
    if (job.empty()) return uncertain("provider_job_reference_invalid");
    if (!on_job(job)) return uncertain("provider_job_journal_failed", job);
    return {"running", "observing", "provider_job_started", {}, job, {}};
  }
  if (*result != 0) return {"failed", "completed", "provider_rejected_" + std::to_string(*result), {}, {}, {}};
  std::vector<std::string> created;
  if (command.operation == journal::operation::checkpoint_create) {
    const auto returned = wmi::text(output.Get(), L"ResultingSnapshot");
    bool found = false;
    const auto rows = wmi::query(services.Get(),
        L"SELECT * FROM Msvm_VirtualSystemSettingData WHERE VirtualSystemIdentifier = '" + vm_id + L"'", 257,
        std::chrono::steady_clock::now() + std::chrono::seconds(5), found);
    if (found) for (const auto& row : rows) {
      if (!returned.empty() && (wmi::text(row.Get(), L"__PATH") == returned || wmi::text(row.Get(), L"__RELPATH") == returned)) created.push_back(snapshot_id(row.Get()));
    }
  }
  return completed(command, created);
}

hyperv_management_progress observe_hyperv_management(const hyperv_management_command& command,
    const std::string& local_provider_job_ref) {
  if (!hyperv::canonical_guid(command.target.vm_source_id) || !journal::local_provider_job_reference(local_provider_job_ref)) return uncertain("provider_job_reference_invalid");
  com_scope com;
  if (!com.initialized) return uncertain("com_initialization_failed", local_provider_job_ref);
  const auto services = connect_provider();
  if (!services) return uncertain("hyperv_provider_unavailable", local_provider_job_ref);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  const auto job = get_local_job(services.Get(), local_provider_job_ref, deadline);
  if (!job) return uncertain("provider_job_missing", local_provider_job_ref);
  const auto ownership = verify_job_ownership(services.Get(), local_provider_job_ref, command.target, deadline);
  if (!ownership.confirmed) return uncertain("provider_job_ownership_unconfirmed", local_provider_job_ref);
  const auto state = wmi::number(job.Get(), L"JobState");
  const auto progress = wmi::number(job.Get(), L"PercentComplete");
  if (!state) return uncertain("provider_job_state_unknown", local_provider_job_ref);
  if (*state >= 2 && *state <= 6) {
    return {"running", "observing", "provider_job_running",
        progress && *progress <= 100 ? std::optional<std::uint16_t>(static_cast<std::uint16_t>(*progress)) : std::nullopt,
        local_provider_job_ref, {}};
  }
  const auto error = wmi::number(job.Get(), L"ErrorCode");
  if (*state == 7 && !error) return uncertain("provider_job_result_unknown", local_provider_job_ref);
  if (*state == 7 && error && *error == 0) return completed(command, ownership.affected_checkpoints, local_provider_job_ref);
  if ((*state >= 7 && *state <= 10) || (error && *error != 0)) {
    return {"failed", "completed", "provider_job_failed_" + std::to_string(error.value_or(0)), {}, local_provider_job_ref, {}};
  }
  return uncertain("provider_job_state_unknown", local_provider_job_ref);
}

}  // namespace ipms::agent::windows
