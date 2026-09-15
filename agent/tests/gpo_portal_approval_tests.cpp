// File Name: gpo_portal_approval_tests.cpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Portal approval bindings and legacy isolation without AD or Agent-state access.
#include "ipms/agent/gpo_management.hpp"
#include <iostream>
#include <limits>

namespace gpo = ipms::agent::gpo;
namespace json = gpo::json;
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F action) {
  bool rejected=false; try {action();} catch(...) {rejected=true;}
  require(rejected,"Unsafe Portal approval was accepted");
}
constexpr std::string_view device_uri="ipms://tenant/device";
const auto now=std::chrono::sys_days(std::chrono::year(2030)/1/1);
json::object document() {
  const auto& c = gpo::components.front();
  json::object fields{{"schema",2},{"approval_mode","portal"},
    {"job_id","11111111-1111-4111-8111-111111111111"},{"input_digest",""},{"operation","create_unlinked_pilot"},
    {"domain_dns_name","example.invalid"},{"domain_guid","22222222-2222-4222-8222-222222222222"},
    {"forest_dns_name","example.invalid"},{"executor_dc_fqdn","dc.example.invalid"},
    {"scope_id","33333333-3333-4333-8333-333333333333"},{"scope_revision",1},{"target_tier",0},
    {"baseline_id",c.baseline_id},{"profile","server"},{"backup_id",c.backup_id},
    {"artifact_sha256",c.artifact_sha256},{"pilot_display_name","0-C-ALL-MSFT-Pilot_V1.0.0"},
    {"expires_at","2030-01-01T00:30:00Z"}};
  fields["input_digest"] = gpo::input_digest(fields);
  return fields;
}
json::object approval(const gpo::job& job) {
  return {{"schema",1},{"job_id",job.text("job_id")},{"input_digest",job.text("input_digest")},
    {"device_uri",device_uri},{"domain_guid",job.text("domain_guid")},{"target_tier",job.number("target_tier")},
    {"operation","create_unlinked_pilot"},{"requested_by","123"},{"approved_by","456"},
    {"approved_at","2030-01-01T00:00:00Z"},{"expires_at",job.text("expires_at")},
    {"policy_revision",1},{"four_eyes_required",true}};
}
gpo::journal intent(const gpo::job& job) {return {job,std::string(device_uri),gpo::phase::granted};}
json::object claim(const gpo::job& job,const json::value& approved) {
  return {{"authorized",true},{"mode","execute"},{"job",job.fields},{"approval",approved}};
}
void save(const gpo::journal& record) {(void)gpo::parse_journal(gpo::journal_document(record));}
gpo::journal grant(const gpo::job& job) {
  auto record=intent(job);const auto approved=approval(job);
  require(gpo::record_claim(record,claim(job,approved),16'000,save,approved,now),"Valid Portal claim rejected");
  return record;
}
struct provider:gpo::pilot_provider {
  std::vector<std::string> calls;
  bool fail_create{};
  std::function<void()> check_create;
  void preflight()override {calls.emplace_back("preflight");}
  std::string create()override {
    calls.emplace_back("create");if(check_create)check_create();
    if(fail_create)throw gpo::operation_error("gpo_provider_failed");
    return "44444444-4444-4444-8444-444444444444";
  }
  void disable(std::string_view)override {calls.emplace_back("disable");}
  void identify(std::string_view)override {calls.emplace_back("identify");}
  void import_settings(std::string_view)override {calls.emplace_back("import");}
  json::object verify(std::string_view)override {
    calls.emplace_back("verify");return {{"computer_enabled",false},{"user_enabled",false},{"unlinked",true},
      {"domain_dns_name","example.invalid"},{"domain_guid","22222222-2222-4222-8222-222222222222"},
      {"dc_fqdn","dc.example.invalid"}};
  }
};
}
int main() {
  try {
    const auto fields=document();const auto job=gpo::parse_job(fields);const auto approved=approval(job);
    require(job.number("schema")==2,"Portal assignment was rejected");
    // Independently calculated with Python SHA-256 over sorted compact UTF-8 JSON.
    require(job.text("input_digest")=="f3e2c648fff748ca87eb73bc43790bed5a2b5a0db15799cac0bb37dc2a202f24",
      "Schema-2 canonical input digest changed");
    require(gpo::parse_portal_approval(approved,job,device_uri)==approved,"Valid approval changed");
    auto legacy_fields=fields;legacy_fields.erase("approval_mode");legacy_fields["schema"]=1;
    legacy_fields["input_digest"]=gpo::input_digest(legacy_fields);const auto legacy=gpo::parse_job(legacy_fields);
    require(legacy.text("input_digest")!=job.text("input_digest"),"Approval mode is not in the assignment digest");
    require(gpo::local_approval_document(legacy,device_uri).size()==3,"Legacy approval contract changed");
    rejects([&]{gpo::local_approval_document(job,device_uri);});
    rejects([&]{gpo::parse_portal_approval(approved,legacy,device_uri);});
    for(const auto schema:{0,1,3}) {
      auto bad=fields;bad["schema"]=schema;bad["input_digest"]=gpo::input_digest(bad);
      rejects([&]{gpo::parse_job(bad);});
    }
    for(const auto mode:{"local","Portal","","portal "}) {
      auto bad=fields;bad["approval_mode"]=mode;bad["input_digest"]=gpo::input_digest(bad);
      rejects([&]{gpo::parse_job(bad);});
    }
    auto bad_job=fields;bad_job.erase("approval_mode");bad_job["input_digest"]=gpo::input_digest(bad_job);
    rejects([&]{gpo::parse_job(bad_job);});
    bad_job=fields;bad_job["approval_mode"]=true;bad_job["input_digest"]=gpo::input_digest(bad_job);
    rejects([&]{gpo::parse_job(bad_job);});
    for(const auto* extra:{"command","script","path","credential","approval"}) {
      auto bad=fields;bad[extra]="unexpected";bad["input_digest"]=gpo::input_digest(bad);
      rejects([&]{gpo::parse_job(bad);});
      auto bad_approval=approved;bad_approval[extra]="unexpected";
      rejects([&]{gpo::parse_portal_approval(bad_approval,job,device_uri);});
    }
    for(const auto& [key,value]:approved) {
      (void)value;auto bad=approved;bad.erase(key);
      rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
    }
    for(const auto* key:{"job_id","input_digest","device_uri","domain_guid","operation","expires_at"}) {
      auto bad=approved;bad[key]="different";
      rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
    }
    for(const auto* key:{"schema","policy_revision","target_tier"}) {
      auto bad=approved;bad[key]=true;
      rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
    }
    auto bad=approved;bad["target_tier"]=1;rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
    bad=approved;bad["schema"]=2;rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
    for(const auto revision:{0,-1}) {bad=approved;bad["policy_revision"]=revision;
      rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});}
    for(const auto* key:{"requested_by","approved_by"}) {
      for(const auto id:{"","0","00","01","-1","+1"," 1","1 ","1.0","1e2","9223372036854775808","10000000000000000000"}) {
        bad=approved;bad[key]=id;rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
      }
      bad=approved;bad[key]=std::string("1\0hidden",8);rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
      bad=approved;bad[key]=123;rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
      bad=approved;bad[key]="9223372036854775807";
      require(gpo::parse_portal_approval(bad,job,device_uri)==bad,"Maximum supported user ID rejected");
    }
    bad=approved;bad["approved_by"]="123";rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
    bad["four_eyes_required"]=false;require(gpo::parse_portal_approval(bad,job,device_uri)==bad,"Single-principal policy rejected");
    bad["four_eyes_required"]="false";rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
    for(const auto timestamp:{"2029-12-31T23:29:59Z","2030-01-01T00:30:00Z","2030-01-01T00:31:00Z",
        "2030-01-01T00:00:00+00:00","2030-01-01T00:00:00.000Z","2030-02-30T00:00:00Z"}) {
      bad=approved;bad["approved_at"]=timestamp;rejects([&]{gpo::parse_portal_approval(bad,job,device_uri);});
    }
    require(gpo::portal_approval_current(approved,job,device_uri,now),"Current approval rejected");
    require(!gpo::portal_approval_current(approved,job,device_uri,now-std::chrono::seconds(1)),"Future approval granted clock grace");
    require(!gpo::portal_approval_current(approved,job,device_uri,now+std::chrono::minutes(30)),"Expired approval accepted");
    bad=approved;bad["approved_at"]="2029-12-31T23:30:00Z";
    require(gpo::portal_approval_current(bad,job,device_uri,now),"Exact one-hour approval interval rejected");
    rejects([&]{gpo::parse_portal_approval(approved,job,"ipms://other/device");});

    for(const auto* changed:{"policy_revision","approved_by","four_eyes_required"}) {
      auto changed_approval=approved;
      if(std::string_view(changed)=="policy_revision") changed_approval[changed]=2;
      else if(std::string_view(changed)=="approved_by") changed_approval[changed]="789";
      else changed_approval[changed]=false;
      auto record=intent(job);rejects([&]{gpo::record_claim(record,claim(job,changed_approval),16'000,save,approved,now);});
      require(record.state==gpo::phase::granted&&record.grant_deadline_tick==0&&record.portal_approval.get_if<std::nullptr_t>(),
        "Mismatched claim changed the durable uncertain intent");
    }
    auto response=claim(job,approved);response.erase("approval");auto record=intent(job);
    rejects([&]{gpo::record_claim(record,response,16'000,save,approved,now);});
    response=claim(job,approved);response["extra"]=true;record=intent(job);
    rejects([&]{gpo::record_claim(record,response,16'000,save,approved,now);});
    auto substituted=fields;substituted["pilot_display_name"]="0-C-ALL-Other-Pilot_V1.0.0";
    substituted["input_digest"]=gpo::input_digest(substituted);const auto other_job=gpo::parse_job(substituted);
    record=intent(job);rejects([&]{gpo::record_claim(record,claim(other_job,approval(other_job)),16'000,save,approved,now);});
    record=intent(job);rejects([&]{gpo::record_claim(record,claim(job,approved),16'000,save,{},now);});
    record=intent(job);rejects([&]{gpo::record_claim(record,claim(job,approved),16'000,save,approved,now+std::chrono::minutes(30));});
    record=intent(legacy);rejects([&]{gpo::record_claim(record,claim(legacy,approved),16'000,save,approved,now);});
    record=intent(job);const json::object cancelled{{"authorized",false},{"mode","cancelled"},{"job",job.fields}};
    require(!gpo::record_claim(record,cancelled,16'000,save,approved,now)&&record.state==gpo::phase::terminal,
      "Definite unclaimed cancellation did not settle");
    provider no_write;gpo::execute_pilot(record,no_write,save,[]{return true;},[]{});
    require(no_write.calls.empty(),"Cancelled Portal claim touched provider");
    for(const auto* mode:{"observe","reconcile","unknown"}) {
      record=intent(job);auto reply=cancelled;reply["mode"]=mode;
      require(!gpo::record_claim(record,reply,16'000,save,approved,now)&&record.state==gpo::phase::reconciliation,
        "Uncertain Portal claim became repeatable");
    }

    record=grant(job);const auto receipt=gpo::portal_approval_receipt(record);
    require(receipt.size()==6&&receipt.at("purpose").as<std::string>()=="portal_gpo_claim"&&
      receipt.at("approval")==json::value(approved),"One-use Portal receipt binding changed");
    require(gpo::grant_current(record,1000)&&gpo::grant_current(record,15'999),"Fresh monotonic grant rejected");
    require(!gpo::grant_current(record,0)&&!gpo::grant_current(record,16'000)&&
      !gpo::grant_current(record,(std::numeric_limits<std::uint64_t>::max)()),"Old, expired or reset-clock grant accepted");
    const auto portal_journal=gpo::journal_document(record);
    require(portal_journal.size()==8&&portal_journal.at("schema").as<std::int64_t>()==2,"Portal journal schema missing");
    require(gpo::parse_journal(portal_journal).portal_approval==json::value(approved),"Claim approval lost in recovery");
    auto corrupt=portal_journal;corrupt["schema"]=1;rejects([&]{gpo::parse_journal(corrupt);});
    corrupt=portal_journal;corrupt["portal_approval"]=json::value{};rejects([&]{gpo::parse_journal(corrupt);});
    corrupt=portal_journal;corrupt["phase"]="prepared";rejects([&]{gpo::parse_journal(corrupt);});
    corrupt=portal_journal;corrupt["grant_deadline_tick"]=0;rejects([&]{gpo::parse_journal(corrupt);});
    auto legacy_record=intent(legacy);legacy_record.grant_deadline_tick=16'000;
    require(gpo::journal_document(legacy_record).size()==7,"Legacy journal encoding changed");
    save(legacy_record);rejects([&]{gpo::portal_approval_receipt(legacy_record);});
    legacy_record.portal_approval=approved;rejects([&]{gpo::journal_document(legacy_record);});
    record=intent(job);rejects([&]{gpo::portal_approval_receipt(record);});
    provider missing;const auto denied=gpo::execute_pilot(record,missing,save,[]{return true;},[]{});
    require(missing.calls.empty()&&denied.at("result_code").as<std::string>()=="gpo_portal_approval_invalid",
      "Missing Portal claim reached provider through legacy/no-op consume callback");

    record=grant(job);provider good;bool consumed=false;std::vector<gpo::phase> persisted;
    good.check_create=[&]{require(consumed&&!persisted.empty()&&persisted.back()==gpo::phase::creating,
      "Portal receipt or durable creating intent missing before CreateGPO");};
    const auto completed=gpo::execute_pilot(record,good,[&](const auto& item){save(item);persisted.push_back(item.state);},
      []{return true;},[&]{consumed=true;});
    require(completed.at("status").as<std::string>()=="staged"&&
      good.calls==std::vector<std::string>{"preflight","create","disable","identify","import","disable","verify"},
      "Portal import changed the disabled/unlinked provider sequence");
    require(gpo::parse_journal(gpo::journal_document(record)).result==json::value(completed),"Completed Portal receipt cannot replay");
    const auto previous_calls=good.calls;require(gpo::execute_pilot(record,good,save,[]{return true;},[]{})==completed&&
      good.calls==previous_calls,"Successful Portal receipt replay repeated writes");
    record=grant(job);provider consumed_failure;
    const auto failed=gpo::execute_pilot(record,consumed_failure,save,[]{return true;},[]{throw gpo::operation_error("gpo_portal_approval_invalid");});
    require(consumed_failure.calls==std::vector<std::string>{"preflight"}&&failed.at("status").as<std::string>()=="failed",
      "Invalid/consumed Portal receipt reached creation");
    record=grant(job);provider disk_failure;
    rejects([&]{gpo::execute_pilot(record,disk_failure,[](const auto&){throw std::runtime_error("disk failure");},[]{return true;},[]{});});
    require(disk_failure.calls==std::vector<std::string>{"preflight"},"Creation preceded durable Portal write intent");
    record=grant(job);provider ambiguous;ambiguous.fail_create=true;
    const auto uncertain=gpo::execute_pilot(record,ambiguous,save,[]{return true;},[]{});
    require(record.state==gpo::phase::reconciliation,"Lost Portal create receipt became retryable");
    const auto uncertain_calls=ambiguous.calls;
    require(gpo::execute_pilot(record,ambiguous,save,[]{return true;},[]{})==uncertain&&ambiguous.calls==uncertain_calls,
      "Portal create ambiguity repeated AD work");

    auto historical_job=fields;historical_job["expires_at"]="2020-01-01T00:30:00Z";
    historical_job["input_digest"]=gpo::input_digest(historical_job);const auto history=gpo::parse_job(historical_job);
    auto historical_approval=approval(history);historical_approval["approved_at"]="2020-01-01T00:00:00Z";
    auto historical=intent(history);
    require(gpo::record_claim(historical,claim(history,historical_approval),16'000,save,historical_approval,
      std::chrono::sys_days(std::chrono::year(2020)/1/1)),"Historical fixture claim failed");
    provider past;gpo::execute_pilot(historical,past,save,[]{return true;},[]{});
    require(!gpo::portal_approval_current(historical_approval,history,device_uri,now),"Historical approval authorizes new execution");
    require(gpo::parse_journal(gpo::journal_document(historical)).result==historical.result,"Expired historical receipt became unreadable");
    require(gpo::valid_result(gpo::result("awaiting_portal_approval","gpo_portal_approval_required")),"Portal waiting status rejected");
    rejects([&]{gpo::result("awaiting_local_approval","gpo_portal_approval_required");});
    rejects([&]{gpo::result("awaiting_portal_approval","gpo_local_approval_required");});
    std::cout << "Portal approval contract checks passed without AD calls.\n";
    return 0;
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
