#include "ipms/agent/hyperv_management_journal.hpp"

#include <array>
#include <stdexcept>

namespace ipms::agent::hyperv_management_journal {
namespace {
namespace json = management_json;
constexpr json::limits result_limits{.document_bytes = 48 * 1024};

[[noreturn]] void invalid() {
  throw std::invalid_argument("Invalid Hyper-V management journal or transition.");
}

bool lower_hex(std::string_view text) {
  for (const char item : text)
    if (!((item >= '0' && item <= '9') || (item >= 'a' && item <= 'f'))) return false;
  return true;
}

bool guid(std::string_view text) {
  if (text.size() != 36) return false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (text[index] != '-') return false;
    } else if (!lower_hex(text.substr(index, 1))) return false;
  }
  return true;
}

bool known(operation item) {
  switch (item) {
    case operation::inspect:
    case operation::checkpoint_create:
    case operation::checkpoint_delete:
    case operation::checkpoint_apply:
    case operation::settings_update: return true;
  }
  return false;
}

bool basic_valid(const journal& item) {
  if (!valid(item.identity)) return false;
  if (!item.provider_job_ref.empty() && !local_provider_job_reference(item.provider_job_ref)) return false;
  switch (item.state) {
    case phase::prepared:
    case phase::invoking:
      return item.provider_job_ref.empty() && item.result_json.empty();
    case phase::observing:
      return !item.provider_job_ref.empty() && item.result_json.empty();
    case phase::requires_reconciliation:
      return item.result_json.empty();
    case phase::terminal:
      return !item.result_json.empty();
  }
  return false;
}

json::value document(const journal& recorded) {
  json::value result;
  if (!recorded.result_json.empty()) {
    result = json::parse(recorded.result_json, result_limits);
    if (!result.get_if<json::object>() || json::serialize(result, result_limits) != recorded.result_json) invalid();
  }
  return json::object{
      {"schema", recorded.identity.schema},
      {"job_id", recorded.identity.job_id},
      {"input_digest", recorded.identity.input_digest},
      {"enrollment_device_uri", recorded.identity.enrollment_device_uri},
      {"operation", name(recorded.identity.action)},
      {"vm_source_id", recorded.identity.vm_source_id},
      {"phase", name(recorded.state)},
      {"provider_job_ref", recorded.provider_job_ref},
      {"result_json", std::move(result)},
  };
}

void require_valid(const journal& recorded) { if (!valid(recorded)) invalid(); }
}  // namespace

std::string_view name(operation item) {
  switch (item) {
    case operation::inspect: return "inspect";
    case operation::checkpoint_create: return "checkpoint_create";
    case operation::checkpoint_delete: return "checkpoint_delete";
    case operation::checkpoint_apply: return "checkpoint_apply";
    case operation::settings_update: return "settings_update";
  }
  invalid();
}

operation parse_operation(std::string_view item) {
  for (const auto candidate : {operation::inspect, operation::checkpoint_create,
                               operation::checkpoint_delete, operation::checkpoint_apply,
                               operation::settings_update})
    if (name(candidate) == item) return candidate;
  invalid();
}

std::string_view name(phase item) {
  switch (item) {
    case phase::prepared: return "prepared";
    case phase::invoking: return "invoking";
    case phase::observing: return "observing";
    case phase::terminal: return "terminal";
    case phase::requires_reconciliation: return "requires_reconciliation";
  }
  invalid();
}

phase parse_phase(std::string_view item) {
  for (const auto candidate : {phase::prepared, phase::invoking, phase::observing,
                               phase::terminal, phase::requires_reconciliation})
    if (name(candidate) == item) return candidate;
  invalid();
}

bool is_mutation(operation item) {
  if (!known(item)) invalid();
  return item != operation::inspect;
}

bool valid(const binding& item) {
  constexpr std::string_view prefix = "urn:ipms:agent:";
  if (item.schema != 1 || !guid(item.job_id) || !guid(item.vm_source_id) ||
      item.input_digest.size() != 64 || !lower_hex(item.input_digest) || !known(item.action) ||
      !item.enrollment_device_uri.starts_with(prefix)) return false;
  const auto device = std::string_view(item.enrollment_device_uri).substr(prefix.size());
  // Enrollment uses UUIDv4 identifiers, matching the certificate URI contract.
  return guid(device) && device[14] == '4' &&
         (device[19] == '8' || device[19] == '9' || device[19] == 'a' || device[19] == 'b');
}

bool local_provider_job_reference(std::string_view item) {
  constexpr std::array prefixes{
      std::string_view("Msvm_ConcreteJob.InstanceID=\""),
      std::string_view("Msvm_MigrationJob.Name=\""),
  };
  if (item.size() > 512 || item.empty() || item.back() != '"') return false;
  for (const auto prefix : prefixes) {
    if (!item.starts_with(prefix)) continue;
    const auto key = item.substr(prefix.size(), item.size() - prefix.size() - 1);
    if (key.empty() || key.size() > 256) return false;
    for (const char next : key) {
      if (!((next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') ||
            (next >= '0' && next <= '9') || next == ':' || next == '-' ||
            next == '_' || next == '.' || next == '{' || next == '}')) return false;
    }
    return true;
  }
  return false;
}

bool valid(const journal& item) {
  if (!basic_valid(item)) return false;
  try {
    // Includes wrapper depth/node/size overhead, not just the nested result.
    (void)json::serialize(document(item));
    return true;
  } catch (const std::invalid_argument&) { return false; }
}

std::string encode(const journal& recorded) {
  if (!basic_valid(recorded)) invalid();
  return json::serialize(document(recorded));
}

journal decode(std::string_view serialized) {
  const auto parsed = json::parse(serialized);
  const auto* fields = parsed.get_if<json::object>();
  if (!fields || fields->size() != 9) invalid();
  const auto string_field = [&](const char* key) -> std::string {
    const auto found = fields->find(key);
    if (found == fields->end()) invalid();
    const auto* text = found->second.get_if<std::string>();
    if (!text) invalid();
    return *text;
  };
  const auto schema = fields->find("schema");
  if (schema == fields->end()) invalid();
  const auto* schema_number = schema->second.get_if<std::int64_t>();
  if (!schema_number || *schema_number != 1) invalid();
  journal recorded;
  recorded.identity = {1, string_field("job_id"), string_field("input_digest"),
                       string_field("enrollment_device_uri"),
                       parse_operation(string_field("operation")), string_field("vm_source_id")};
  recorded.state = parse_phase(string_field("phase"));
  recorded.provider_job_ref = string_field("provider_job_ref");
  const auto result = fields->find("result_json");
  if (result == fields->end()) invalid();
  if (result->second.get_if<json::object>())
    recorded.result_json = json::serialize(result->second, result_limits);
  else if (!result->second.get_if<std::nullptr_t>()) invalid();
  require_valid(recorded);
  return recorded;
}

journal prepare(const binding& identity) {
  if (!valid(identity)) invalid();
  return {identity, phase::prepared, {}, {}};
}

delivery_action on_delivery(const journal& recorded, const binding& incoming) {
  if (!valid(incoming) || !valid(recorded) || recorded.identity != incoming) return delivery_action::reject;
  switch (recorded.state) {
    case phase::prepared: return delivery_action::invoke;
    case phase::invoking:
    case phase::requires_reconciliation: return delivery_action::reconcile;
    case phase::observing: return delivery_action::resume_observation;
    case phase::terminal: return delivery_action::report_terminal;
  }
  return delivery_action::reject;
}

journal begin_invocation(const journal& recorded) {
  require_valid(recorded);
  if (recorded.state != phase::prepared) invalid();
  auto next = recorded;
  next.state = phase::invoking;
  return next;
}

journal begin_observation(const journal& recorded, std::string_view local_job) {
  require_valid(recorded);
  if (recorded.state != phase::invoking || !local_provider_job_reference(local_job)) invalid();
  auto next = recorded;
  next.state = phase::observing;
  next.provider_job_ref = local_job;
  require_valid(next);
  return next;
}

journal complete(const journal& recorded, const management_json::value& result) {
  require_valid(recorded);
  if (!result.get_if<json::object>()) invalid();
  const auto serialized = json::serialize(result, result_limits);
  if (recorded.state == phase::terminal) {
    if (recorded.result_json != serialized) invalid();
    return recorded;
  }
  if (recorded.state == phase::prepared) {
    const auto& fields = result.as<json::object>();
    const auto status = fields.find("status");
    const auto stage = fields.find("phase");
    if (status == fields.end() || stage == fields.end() ||
        !status->second.get_if<std::string>() || status->second.as<std::string>() != "failed" ||
        !stage->second.get_if<std::string>() || stage->second.as<std::string>() != "preflight") invalid();
  } else if (recorded.state != phase::invoking && recorded.state != phase::observing) invalid();
  auto next = recorded;
  next.state = phase::terminal;
  next.result_json = serialized;
  require_valid(next);
  return next;
}

journal recover(const journal& recorded) {
  require_valid(recorded);
  if (recorded.state != phase::invoking) return recorded;
  return require_reconciliation(recorded);
}

journal require_reconciliation(const journal& recorded) {
  require_valid(recorded);
  if (recorded.state != phase::invoking && recorded.state != phase::observing &&
      recorded.state != phase::requires_reconciliation) invalid();
  auto next = recorded;
  next.state = phase::requires_reconciliation;
  return next;
}

}  // namespace ipms::agent::hyperv_management_journal
