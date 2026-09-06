#include "ipms/agent/hyperv_management_journal.hpp"
#include "ipms/agent/management_json.hpp"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace json = ipms::agent::management_json;
namespace journal = ipms::agent::hyperv_management_journal;

namespace {
std::size_t checks{};

void require(bool condition, const char* message) {
  ++checks;
  if (!condition) throw std::runtime_error(message);
}

template <typename F> void rejected(F action, const char* message) {
  bool failed{};
  try { action(); } catch (const std::invalid_argument&) { failed = true; }
  require(failed, message);
}

journal::binding identity() {
  return {1, "11111111-1111-4111-8111-111111111111", std::string(64, 'a'),
          "urn:ipms:agent:22222222-2222-4222-8222-222222222222",
          journal::operation::checkpoint_create,
          "33333333-3333-4333-8333-333333333333"};
}

void parser_contract() {
  const std::vector<std::pair<std::string, std::string>> vectors{
      {" null \r\n\t", "null"}, {"true", "true"}, {"false", "false"},
      {"-0", "0"}, {"9223372036854775807", "9223372036854775807"},
      {"-9223372036854775808", "-9223372036854775808"},
      {"{\"z\":[1,false,null],\"a\":{\"b\":2}}", "{\"a\":{\"b\":2},\"z\":[1,false,null]}"},
      {"\"\\u0061\\/\\b\\f\\n\\r\\t\\\\\\\"\"", "\"a/\\b\\f\\n\\r\\t\\\\\\\"\""},
      {"\"\\u0000\\u001f\"", "\"\\u0000\\u001f\""},
      {"\"\\uD83D\\uDE00\"", "\"\xf0\x9f\x98\x80\""},
      {"\"\\uDBFF\\uDFFF\"", "\"\xf4\x8f\xbf\xbf\""},
      {"\"\xc3\xa4\xe2\x82\xac\"", "\"\xc3\xa4\xe2\x82\xac\""},
      {"{\"z\":0,\"\\u0061\":1}", "{\"a\":1,\"z\":0}"},
  };
  for (const auto& [source, expected] : vectors) {
    const auto parsed = json::parse(source);
    require(json::serialize(parsed) == expected, "Canonical JSON vector mismatch.");
    require(json::parse(expected) == parsed, "Canonical JSON failed round trip.");
  }
  require(json::parse("\"\\u0000\"").as<std::string>().size() == 1,
          "JSON parsing must preserve decoded NUL for typed validation.");
  const std::vector<std::string> invalid{
      "", " ", "null false", "True", "undefined", "NaN", "Infinity",
      "01", "-01", "+1", "-", "1.0", "1e2", "1E+2", "0x10",
      "9223372036854775808", "-9223372036854775809", "[1,]", "[,1]",
      "{\"a\":1,}", "{a:1}", "{\"a\" 1}", "[true false]", "/*x*/null",
      "{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}",
      "{\"x\":{\"a\":1,\"a\":2}}", "\"\\uD800\"", "\"\\uDC00\"",
      "\"\\uD800\\u0041\"", "\"\\uD800x\"", "\"\\u12xy\"", "\"\\u123\"",
      "\"\\x20\"", "\"\\v\"", "\"unfinished", "\"raw\nline\"",
      "\"\xc0\xaf\"", "\"\xed\xa0\x80\"", "\"\xf4\x90\x80\x80\"",
      "\"\xe0\x80\xaf\"", "\"\xf0\x80\x80\xaf\"", "\"\xc2\x41\"",
      "\"\x80\"", "\"\xc2\"", "\"\xe2\x82\"", "\"\xf5\x80\x80\x80\"",
      std::string("\"\0\"", 3), std::string("null\0", 5), "\xef\xbb\xbfnull",
  };
  for (const auto& item : invalid)
    rejected([&] { (void)json::parse(item); }, "Malformed JSON was accepted.");
  rejected([] { (void)json::serialize(json::value(std::string("\xc0\xaf"))); },
           "Serializer accepted malformed UTF-8 value.");
  rejected([] { (void)json::serialize(json::object{{std::string("\x80"), 1}}); },
           "Serializer accepted malformed UTF-8 key.");
  rejected([] { (void)json::value(std::numeric_limits<std::uint64_t>::max()); },
           "Value constructor accepted overflowing unsigned integer.");

  require(json::parse(std::string(8, '[') + "0" + std::string(8, ']')).as<json::array>().size() == 1,
          "Eight levels must be accepted.");
  rejected([] { (void)json::parse(std::string(9, '[') + "0" + std::string(9, ']')); },
           "Parser exceeded depth limit.");
  json::value nested = 0;
  for (int level = 0; level < 9; ++level) nested = json::array{nested};
  rejected([&] { (void)json::serialize(nested); }, "Serializer exceeded depth limit.");
  const std::string max_string(16 * 1024, 'a');
  require(json::parse("\"" + max_string + "\"").as<std::string>() == max_string,
          "String limit boundary was rejected.");
  rejected([&] { (void)json::parse("\"" + max_string + "a\""); }, "Parser exceeded string limit.");
  rejected([&] { (void)json::serialize(max_string + "a"); }, "Serializer exceeded string limit.");
  std::string escaped;
  for (int index = 0; index < 8200; ++index) escaped += "\\u00e4";
  rejected([&] { (void)json::parse("\"" + escaped + "\""); }, "Decoded UTF-8 string limit was bypassed.");
  json::array max_nodes(4095, 0);
  const auto max_nodes_json = json::serialize(max_nodes);
  require(json::parse(max_nodes_json).as<json::array>().size() == 4095, "Node boundary rejected.");
  max_nodes.emplace_back(0);
  rejected([&] { (void)json::serialize(max_nodes); }, "Serializer exceeded node limit.");
  rejected([&] { (void)json::parse(max_nodes_json.substr(0, max_nodes_json.size() - 1) + ",0]"); },
           "Parser exceeded node limit.");
  rejected([] { (void)json::parse("{\"a\":0}", {.nodes=2}); }, "Object key did not count toward nodes.");
  require(json::parse(std::string(65532, ' ') + "null").data.index() == 0, "Document boundary rejected.");
  rejected([] { (void)json::parse(std::string(65533, ' ') + "null"); }, "Document limit exceeded.");
  const json::value large = json::array{max_string, max_string, max_string, max_string};
  rejected([&] { (void)json::serialize(large); }, "Serializer exceeded default document limit.");
  rejected([] { (void)json::parse("null", {.document_bytes=65537}); }, "Hard document limit raised.");
  require(json::serialize(json::object{{"a", 1}}, {.document_bytes=7}) == "{\"a\":1}",
          "Explicit lower document limit failed.");
  rejected([] { (void)json::serialize(json::object{{"a", 1}}, {.document_bytes=6}); },
           "Lower document limit ignored.");
  rejected([] { (void)json::parse("null", {.depth=9}); }, "Hard depth limit raised.");
  rejected([] { (void)json::parse("null", {.nodes=4097}); }, "Hard node limit raised.");
  rejected([] { (void)json::parse("null", {.string_bytes=16385}); }, "Hard string limit raised.");
  rejected([] { (void)json::parse("null", {.nodes=0}); }, "Zero node budget accepted.");
  require(json::parse("0", {.depth=0}).as<std::int64_t>() == 0, "Scalar depth zero rejected.");
  rejected([] { (void)json::parse("[]", {.depth=0}); }, "Container accepted at zero depth.");
  require(json::parse("\"\"", {.string_bytes=0}).as<std::string>().empty(), "Empty string budget rejected.");

  // Deterministic byte-mutation corpus exercises lexer boundaries and decoded
  // UTF-8 under sanitizers. It is a round-trip property, not a grammar oracle.
  const std::string seed = "{\"a\":[1,\"\\u0061\"],\"b\":null}";
  for (std::size_t position = 0; position < seed.size(); ++position) {
    for (unsigned byte = 0; byte <= 255; ++byte) {
      auto mutation = seed;
      mutation[position] = static_cast<char>(byte);
      try {
        const auto parsed = json::parse(mutation);
        const auto canonical = json::serialize(parsed);
        require(json::parse(canonical) == parsed, "Byte mutation broke canonical round trip.");
      } catch (const std::invalid_argument&) {
        // Rejection is expected for invalid byte/grammar combinations.
      }
    }
  }
}

void journal_contract() {
  const auto expected = identity();
  require(journal::valid(expected), "Valid binding rejected.");
  auto prepared = journal::prepare(expected);
  require(journal::on_delivery(prepared, expected) == journal::delivery_action::invoke,
          "Prepared operation cannot invoke.");
  require(journal::recover(prepared) == prepared, "Prepared journal changed on recovery.");
  auto invoking = journal::begin_invocation(prepared);
  require(journal::on_delivery(invoking, expected) == journal::delivery_action::reconcile,
          "Duplicate invoking delivery could mutate again.");
  rejected([&] { (void)journal::begin_invocation(invoking); }, "Repeated invocation transition accepted.");
  const auto uncertain = journal::recover(invoking);
  require(uncertain.state == journal::phase::requires_reconciliation, "Crash window did not fence invocation.");
  require(journal::on_delivery(uncertain, expected) == journal::delivery_action::reconcile,
          "Uncertain result retried mutation.");
  rejected([&] { (void)journal::begin_invocation(uncertain); }, "Reconciliation bypassed.");
  const std::string local_job = "Msvm_ConcreteJob.InstanceID=\"44444444-4444-4444-8444-444444444444\"";
  auto observing = journal::begin_observation(invoking, local_job);
  require(journal::recover(observing) == observing, "Known provider job lost on restart.");
  require(journal::on_delivery(observing, expected) == journal::delivery_action::resume_observation,
          "Observing delivery did not resume monitoring.");
  rejected([&] { (void)journal::begin_invocation(observing); }, "Observing job could invoke again.");
  const json::value outcome = json::object{{"result_code", "completed"}, {"succeeded", true}};
  auto terminal = journal::complete(observing, outcome);
  require(journal::recover(terminal) == terminal, "Terminal outcome lost on restart.");
  require(journal::on_delivery(terminal, expected) == journal::delivery_action::report_terminal,
          "Terminal delivery did not replay only result.");
  require(journal::complete(terminal, outcome) == terminal, "Identical terminal completion not idempotent.");
  rejected([&] { (void)journal::complete(terminal, json::object{{"succeeded", false}}); },
           "Conflicting terminal result accepted.");
  rejected([&] { (void)journal::complete(prepared, outcome); }, "Uninvoked job falsely completed.");
  const auto preflight = journal::complete(prepared, json::object{{"status", "failed"}, {"phase", "preflight"}});
  require(preflight.state == journal::phase::terminal && preflight.provider_job_ref.empty(),
          "A known preflight failure could not settle without invoking the provider.");
  rejected([&] { (void)journal::complete(prepared, json::object{{"status", "succeeded"}, {"phase", "preflight"}}); },
           "A prepared operation falsely claimed provider success.");
  rejected([&] { (void)journal::complete(uncertain, outcome); }, "Reconciliation silently marked successful.");
  rejected([&] { (void)journal::complete(invoking, json::array{}); }, "Nonobject terminal result accepted.");
  require(journal::complete(invoking, outcome).state == journal::phase::terminal,
          "Synchronous provider completion rejected.");
  require(journal::require_reconciliation(observing).state == journal::phase::requires_reconciliation,
          "Lost provider observation did not fence job.");
  rejected([&] { (void)journal::require_reconciliation(terminal); }, "Terminal history rewritten.");

  for (int field = 0; field < 6; ++field) {
    auto changed = expected;
    if (field == 0) changed.schema = 2;
    if (field == 1) changed.job_id[0] = '9';
    if (field == 2) changed.input_digest[0] = 'b';
    if (field == 3) changed.enrollment_device_uri.back() = '9';
    if (field == 4) changed.action = journal::operation::checkpoint_delete;
    if (field == 5) changed.vm_source_id[0] = '9';
    for (const auto& state : {prepared, invoking, observing, terminal, uncertain})
      require(journal::on_delivery(state, changed) == journal::delivery_action::reject,
              "Journal identity mismatch was not rejected.");
  }
  for (const auto& ref : {"\\\\remote\\root\\virtualization\\v2:Msvm_ConcreteJob.InstanceID=\"x\"",
                          "ROOT\\Virtualization\\V2:Msvm_ConcreteJob.InstanceID=\"x\"",
                          "Win32_Process.Handle=\"1\"", "Msvm_ConcreteJob.InstanceID=\"x\\y\"",
                          "Msvm_ConcreteJob.InstanceID=\"x\".DeleteInstance", ""}) {
    require(!journal::local_provider_job_reference(ref), "Nonlocal or unapproved job reference accepted.");
    rejected([&] { (void)journal::begin_observation(invoking, ref); }, "Unsafe provider reference stored.");
  }
  std::string nul_reference = "Msvm_ConcreteJob.InstanceID=\"x";
  nul_reference.push_back('\0');
  nul_reference += "y\"";
  require(!journal::local_provider_job_reference(nul_reference), "NUL provider reference accepted.");
  for (const auto action : {journal::operation::inspect, journal::operation::checkpoint_create,
                            journal::operation::checkpoint_delete, journal::operation::checkpoint_apply,
                            journal::operation::settings_update})
    require(journal::parse_operation(journal::name(action)) == action, "Operation enum round trip failed.");
  for (const auto state : {journal::phase::prepared, journal::phase::invoking, journal::phase::observing,
                           journal::phase::terminal, journal::phase::requires_reconciliation})
    require(journal::parse_phase(journal::name(state)) == state, "Phase enum round trip failed.");
  rejected([] { (void)journal::parse_operation("migration"); }, "Future operation accidentally enabled.");
  rejected([] { (void)journal::parse_operation("shell"); }, "Arbitrary operation enabled.");
  rejected([] { (void)journal::parse_phase("retry"); }, "Unknown phase accepted.");
  require(!journal::is_mutation(journal::operation::inspect), "Inspection considered mutation.");
  require(journal::is_mutation(journal::operation::checkpoint_apply), "Checkpoint apply considered read-only.");
  auto corrupt = observing;
  corrupt.provider_job_ref.clear();
  require(!journal::valid(corrupt), "Missing observing reference accepted.");
  corrupt = prepared;
  corrupt.result_json = "{}";
  require(!journal::valid(corrupt), "Premature result accepted.");
  corrupt = terminal;
  corrupt.result_json = "{\"a\":1,\"a\":2}";
  require(!journal::valid(corrupt), "Corrupt terminal result accepted.");
  corrupt = prepared;
  corrupt.identity.job_id += '\0';
  require(!journal::valid(corrupt), "NUL typed identity accepted.");
  rejected([&] { (void)journal::recover(corrupt); }, "Corrupt journal recovered as actionable.");

  for (const auto& state : {prepared, invoking, observing, terminal, uncertain}) {
    const auto encoded = journal::encode(state);
    require(journal::decode(encoded) == state, "Journal persistence round trip failed.");
    require(journal::encode(journal::decode(encoded)) == encoded, "Journal codec was not deterministic.");
    require(journal::recover(journal::decode(encoded)) == journal::recover(state),
            "Persistence changed restart decision.");
  }
  auto encoded = json::parse(journal::encode(terminal)).as<json::object>();
  require(encoded.at("result_json").get_if<json::object>() != nullptr,
          "Journal result was double-escaped.");
  encoded.emplace("command", "shell");
  rejected([&] { (void)journal::decode(json::serialize(encoded)); }, "Unknown journal key accepted.");
  encoded.erase("command");
  encoded.at("schema") = true;
  rejected([&] { (void)journal::decode(json::serialize(encoded)); }, "Boolean journal schema accepted.");
  encoded.at("schema") = 1;
  encoded.at("result_json") = "{}";
  rejected([&] { (void)journal::decode(json::serialize(encoded)); }, "String journal result accepted.");
  encoded.at("result_json") = nullptr;
  rejected([&] { (void)journal::decode(json::serialize(encoded)); }, "Terminal journal lacked result.");
  encoded.erase("phase");
  rejected([&] { (void)journal::decode(json::serialize(encoded)); }, "Missing journal key accepted.");
}
}  // namespace

int main() {
  try {
    parser_contract();
    journal_contract();
    std::cout << "Hyper-V management contract: " << checks << " checks passed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "Hyper-V management contract failed after " << checks << " checks: " << error.what() << '\n';
    return 1;
  }
}
