#pragma once

#include "ipms/agent/management_json.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace ipms::agent::hyperv_management_journal {

enum class operation {
  inspect,
  checkpoint_create,
  checkpoint_delete,
  checkpoint_apply,
  settings_update,
};

enum class phase {
  prepared,
  invoking,
  observing,
  terminal,
  requires_reconciliation,
};

enum class delivery_action {
  invoke,
  resume_observation,
  report_terminal,
  reconcile,
  reject,
};

struct binding {
  std::uint32_t schema{1};
  std::string job_id;
  std::string input_digest;
  std::string enrollment_device_uri;
  operation action{operation::inspect};
  std::string vm_source_id;
  bool operator==(const binding&) const = default;
};

struct journal {
  binding identity;
  phase state{phase::prepared};
  // Only a locally returned relative job reference is accepted. The transport
  // must never obtain this field from a management assignment.
  std::string provider_job_ref;
  // Empty unless terminal; otherwise canonical, bounded JSON object text.
  std::string result_json;
  bool operator==(const journal&) const = default;
};

std::string_view name(operation item);
operation parse_operation(std::string_view item);
std::string_view name(phase item);
phase parse_phase(std::string_view item);
bool is_mutation(operation item);
bool valid(const binding& item);
bool valid(const journal& item);
bool local_provider_job_reference(std::string_view item);
// Exact-key, bounded persistence codec. result_json is an embedded object (or
// null), not double-escaped string data. Decoding grants no execution authority.
std::string encode(const journal& recorded);
journal decode(std::string_view document);

journal prepare(const binding& identity);
delivery_action on_delivery(const journal& recorded, const binding& incoming);

// Pure transitions return a replacement record. The integration MUST persist
// invoking atomically and durably before calling the provider, and serialize
// access to this journal. This library alone does not provide exactly-once I/O.
journal begin_invocation(const journal& recorded);
journal begin_observation(const journal& recorded, std::string_view local_job);
// A prepared record may terminate only as an explicit failed preflight, never
// as a successful provider write without persisted invocation intent.
journal complete(const journal& recorded, const management_json::value& result);

// Recovery never retries an invocation whose acceptance was not durably known.
// Observation and terminal replay are safe only after enrollment/binding checks.
journal recover(const journal& recorded);
journal require_reconciliation(const journal& recorded);

}  // namespace ipms::agent::hyperv_management_journal
