#pragma once

#include "ipms/agent/hyperv_management_journal.hpp"

#include <functional>
#include <optional>
#include <string>

namespace ipms::agent::windows {

struct hyperv_management_target {
  std::string vm_source_id;
  std::string expected_name;
};

struct hyperv_management_inspection {
  bool succeeded{false};
  std::string result_code;
  std::string document_json;
  // Bounded local diagnostic only; not part of the portal snapshot contract.
  // Provider metadata is not evidence that any mutation has been validated.
  std::string provider_schema_json;
};

// A fixed, bounded, local read. No WMI text, method, object path, credentials,
// or remote endpoint can be supplied by the caller. Inspection never invokes
// a provider method and never authorizes a subsequent write by itself.
hyperv_management_inspection inspect_hyperv_virtual_machine(
    const hyperv_management_target& target);

struct hyperv_management_command {
  hyperv_management_target target;
  hyperv_management_journal::operation operation;
  std::string expected_revision;
  management_json::value parameters;
};

struct hyperv_management_progress {
  std::string status;
  std::string phase;
  std::string result_code;
  std::optional<std::uint16_t> progress;
  std::string provider_job_ref;
  std::string snapshot_json;
};

// Caller must durably record invoking (and check its execution lease) in
// before_invoke. The callback returning false prevents every provider write.
// on_job must durably record the locally returned relative job reference.
// Never repeat execute after an uncertain acceptance: resume observation or
// request reconciliation instead. Neither callback may be omitted.
hyperv_management_progress execute_hyperv_management(
    const hyperv_management_command& command,
    const std::function<bool()>& before_invoke,
    const std::function<bool(const std::string&)>& on_job);

// Read-only resumption. The relative reference originates exclusively from
// the local journal, and its provider association must identify this VM.
hyperv_management_progress observe_hyperv_management(
    const hyperv_management_command& command,
    const std::string& local_provider_job_ref);

}  // namespace ipms::agent::windows
