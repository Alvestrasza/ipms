#include "ipms/agent/hyperv_management.hpp"

#include <iostream>

namespace journal = ipms::agent::hyperv_management_journal;
namespace json = ipms::agent::management_json;
using namespace ipms::agent::windows;

// These tests deliberately never resolve a real VM or invoke a WMI method.
int main() {
  const auto inspection = inspect_hyperv_virtual_machine({"not-a-guid", "Disposable VM"});
  if (inspection.succeeded || inspection.result_code != "invalid_vm_identity" ||
      !inspection.document_json.empty() || !inspection.provider_schema_json.empty()) return 1;
  hyperv_management_command command{{"not-a-guid", "Disposable VM"},
      journal::operation::checkpoint_create, std::string(64, 'a'), json::object{{"policy", "configured"}}};
  unsigned journal_calls = 0;
  const auto before = [&] { ++journal_calls; return true; };
  const auto accepted = [&](const std::string&) { ++journal_calls; return true; };
  const auto execution = execute_hyperv_management(command, before, accepted);
  if (execution.status != "failed" || execution.result_code != "invalid_vm_identity" || journal_calls != 0) return 2;
  const auto missing_journal = execute_hyperv_management(command, {}, accepted);
  if (missing_journal.result_code != "execution_journal_required" || journal_calls != 0) return 3;
  command.target.vm_source_id = "12345678-1234-1234-1234-123456789abc";
  const auto remote_job = observe_hyperv_management(command,
      "\\\\untrusted.invalid\\root\\virtualization\\v2:Msvm_ConcreteJob.InstanceID=\"one\"");
  if (remote_job.status != "requires_reconciliation" || remote_job.result_code != "provider_job_reference_invalid") return 4;
  const auto injected_job = observe_hyperv_management(command, "Msvm_ConcreteJob.InstanceID=\"one\" OR true");
  if (injected_job.result_code != "provider_job_reference_invalid") return 5;
  std::cout << "Hyper-V native management boundaries passed without contacting a VM.\n";
  return 0;
}
