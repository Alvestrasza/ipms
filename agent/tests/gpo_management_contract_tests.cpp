// File Name: gpo_management_contract_tests.cpp
// Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Independent hash vectors, hostile artifacts and no-retry pilot write boundaries.
#include "ipms/agent/gpo_management.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

namespace gpo=ipms::agent::gpo;
namespace json=gpo::json;
namespace {
void require(bool c,const char* m){if(!c)throw std::runtime_error(m);}
template<class F>void rejects(F f){bool rejected=false;try{f();}catch(...){rejected=true;}require(rejected,"Unsafe input accepted");}
json::object document() {
  const auto& c=gpo::components.front();
  json::object f{{"schema",1},{"job_id","11111111-1111-4111-8111-111111111111"},{"input_digest",""},{"operation","create_unlinked_pilot"},
    {"domain_dns_name","example.invalid"},{"domain_guid","22222222-2222-4222-8222-222222222222"},{"forest_dns_name","example.invalid"},
    {"executor_dc_fqdn","dc.example.invalid"},{"scope_id","33333333-3333-4333-8333-333333333333"},{"scope_revision",1},
    {"target_tier",0},{"baseline_id",c.baseline_id},{"profile","server"},{"backup_id",c.backup_id},
    {"artifact_sha256",c.artifact_sha256},{"pilot_display_name","0-C-ALL-MSFT-Pilot_V1.0.0"},{"expires_at","2030-01-01T00:30:00Z"}};
  f["input_digest"]=gpo::input_digest(f);return f;
}
json::object evidence(){return {{"computer_enabled",false},{"user_enabled",false},{"unlinked",true},{"domain_dns_name","example.invalid"},
    {"domain_guid","22222222-2222-4222-8222-222222222222"},{"dc_fqdn","dc.example.invalid"}};}
struct provider:gpo::pilot_provider {
  std::vector<std::string> calls;
  std::string failure;
  std::string id="44444444-4444-4444-8444-444444444444";
  void step(const char* call){calls.emplace_back(call);if(failure==call)throw gpo::operation_error("gpo_permission_denied");}
  void preflight()override{step("preflight");}
  std::string create()override{step("create");return id;}
  void disable(std::string_view)override{step("disable");}
  void identify(std::string_view)override{step("identify");}
  void import_settings(std::string_view)override{step("import");}
  json::object verify(std::string_view)override{step("verify");return evidence();}
};
gpo::journal journal(){return {gpo::parse_job(document()),"ipms://tenant/device",gpo::phase::granted,"",1000,{}};}
void append_u32(std::vector<std::uint8_t>& v,std::uint32_t n){for(unsigned i=0;i<4;++i)v.push_back(static_cast<std::uint8_t>(n>>(i*8)));}
}
int main(int argc,char** argv) {
  try {
    require(gpo::sha256("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","SHA256 empty vector");
    require(gpo::sha256("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 abc vector");
    require(gpo::sha256(std::string(1000000,'a'))=="cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0","SHA256 multiblock vector");
    auto f=document();const auto j=gpo::parse_job(f);require(gpo::component(j)!=nullptr,"Known component missing");
    require(j.text("input_digest")=="cb112f403446ecdd3e3e1ead6e73251b3fba5a1c4e00a07986df59761721163d","Independent canonical JSON digest differs");
    for(const auto* key:{"command","path","gpo_guid","acl","script","links"}){auto bad=f;bad[key]="unexpected";bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});}
    auto bad=f;bad["target_tier"]=3;bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
    bad=f;bad["domain_guid"]="00000000-0000-0000-0000-000000000000";bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
    bad=f;bad["scope_revision"]=0;bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
    bad=f;bad["pilot_display_name"]=std::string("Safe\0Hidden",11);bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
    bad=f;bad["pilot_display_name"]=std::string(240,'A');bad["input_digest"]=gpo::input_digest(bad);
    require(gpo::parse_job(bad).text("pilot_display_name").size()==240,"Portal 240-byte pilot name rejected");
    bad["pilot_display_name"]=std::string(241,'A');bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
    bad=f;bad["pilot_display_name"]="changed without digest";rejects([&]{gpo::parse_job(bad);});
    for(const auto s:{"2030-02-30T00:00:00Z","2030-01-01T00:00:00+00:00","2030-01-01T24:00:00Z"}){
      bad=f;bad["expires_at"]=s;bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});}
    const auto now=std::chrono::sys_days(std::chrono::year(2030)/1/1);
    require(gpo::unexpired(j,now),"Valid expiry rejected");require(!gpo::unexpired(j,now+std::chrono::hours(1)),"Expired job accepted");
    require(!gpo::unexpired(j,now-std::chrono::hours(1)),"Overlong authorization accepted");
    for(const auto s:{"{31B2F340-016D-11D2-945F-00C04FB984F9}","6ac1786c-016f-11d2-945f-00c04fb984f9"}) require(gpo::protected_gpo(s),"Default GPO identity unprotected");
    auto e=evidence();json::object executor{{"role","writable-domain-controller"},{"gpmc_available",true},
      {"domain_dns_name","example.invalid"},{"domain_guid",j.text("domain_guid")},{"forest_dns_name","example.invalid"},{"dc_fqdn","dc.example.invalid"}};
    require(gpo::executor_matches(j,executor),"Correct DC rejected");executor["role"]="read-only-domain-controller";require(!gpo::executor_matches(j,executor),"RODC accepted");
    executor["role"]="writable-domain-controller";executor["domain_guid"]="55555555-5555-4555-8555-555555555555";require(!gpo::executor_matches(j,executor),"Different domain accepted");
    auto managed_routing=journal();managed_routing.assignment.fields["schema"]=3;provider wrong_provider;
    rejects([&]{gpo::execute_pilot(managed_routing,wrong_provider,[](const auto&){},[]{return true;},[]{});});
    require(wrong_provider.calls.empty(),"Managed assignment reached legacy provider without snapshot guards");
    auto rec=journal();require(gpo::parse_journal(gpo::journal_document(rec)).assignment==rec.assignment,"Journal binding changed");
    rec.grant_deadline_tick=0;const json::object cancellation{{"authorized",false},{"mode","cancelled"},{"job",rec.assignment.fields}};
    require(!gpo::record_claim(rec,cancellation,1000,[](const auto&){})&&rec.state==gpo::phase::terminal&&
        rec.result.as<json::object>().at("result_code").as<std::string>()=="gpo_authority_expired","Definitive cancellation retained a permanent claim fence");
    provider cancelled_provider;gpo::execute_pilot(rec,cancelled_provider,[](const auto&){},[]{return true;},[]{});
    require(cancelled_provider.calls.empty()&&rec.gpo_guid.empty(),"Cancelled claim reached AD");
    require(gpo::parse_journal(gpo::journal_document(rec)).state==gpo::phase::terminal,"Cancellation cannot resume normal polling");
    for(const auto mode:{"observe","reconcile","unknown"}){
      rec=journal();rec.grant_deadline_tick=0;
      require(!gpo::record_claim(rec,json::object{{"authorized",false},{"mode",mode},{"job",rec.assignment.fields}},1000,[](const auto&){})&&
          rec.state==gpo::phase::reconciliation,"Uncertain claim was released");}
    rec=journal();rejects([&]{gpo::record_claim(rec,cancellation,2000,[](const auto&){});});
    rec=journal();rec.grant_deadline_tick=0;
    require(gpo::record_claim(rec,json::object{{"authorized",true},{"mode","execute"},{"job",rec.assignment.fields}},1000,[](const auto&){}),"First execution grant rejected");
    provider p;std::vector<gpo::phase> saved;bool consumed=false;
    auto r=gpo::execute_pilot(rec,p,[&](const auto& item){saved.push_back(item.state);},[]{return true;},[&]{consumed=true;});
    require(r.at("status").as<std::string>()=="staged"&&consumed,"Valid pilot failed");
    require(p.calls==std::vector<std::string>{"preflight","create","disable","identify","import","disable","verify"},"Provider write sequence changed");
    require(saved==std::vector<gpo::phase>{gpo::phase::creating,gpo::phase::created,gpo::phase::importing,gpo::phase::terminal},"Write intent not persisted first");
    require(gpo::valid_result(r),"Valid receipt rejected");r.at("evidence").as<json::object>()["computer_enabled"]=true;require(!gpo::valid_result(r),"Enabled pilot receipt accepted");
    for(const auto stage:{"preflight","create","disable","identify","import","verify"}){
      rec=journal();provider failing;failing.failure=stage;
      const auto outcome=gpo::execute_pilot(rec,failing,[](const auto&){},[]{return true;},[]{});
      require(outcome.at("status").as<std::string>()==(std::string(stage)=="preflight"?"failed":"requires_reconciliation"),"Ambiguous write was retryable");
      const auto persisted=gpo::parse_journal(gpo::journal_document(rec));
      require(persisted.result==json::value(outcome),"Exact failure receipt was not durable");
      const auto prior=failing.calls;const auto replay=gpo::execute_pilot(rec,failing,[](const auto&){},[]{return true;},[]{});
      require(json::value(replay)==json::value(outcome),"Receipt replay changed its digest");
      require(failing.calls==prior,"Re-delivery repeated a write");
    }
    rec=journal();provider denied;gpo::execute_pilot(rec,denied,[](const auto&){},[]{return false;},[]{});require(denied.calls.empty(),"Expired grant contacted provider");
    rec=journal();provider protected_target;protected_target.id="31b2f340-016d-11d2-945f-00c04fb984f9";
    gpo::execute_pilot(rec,protected_target,[](const auto&){},[]{return true;},[]{});
    require(protected_target.calls==std::vector<std::string>{"preflight","create"},"Default GPO received a write");
    rec=journal();provider disk_failure;
    rejects([&]{gpo::execute_pilot(rec,disk_failure,[](const auto&){throw std::runtime_error("disk failed");},[]{return true;},[]{});});
    require(disk_failure.calls==std::vector<std::string>{"preflight"},"Create called before durable intent");
    rec=journal();provider no_approval;
    const auto refused=gpo::execute_pilot(rec,no_approval,[](const auto&){},[]{return true;},[]{throw gpo::operation_error("gpo_local_approval_invalid");});
    require(no_approval.calls==std::vector<std::string>{"preflight"}&&refused.at("status").as<std::string>()=="failed","Absent local approval reached CreateGPO");
    auto corrupt_journal=gpo::journal_document(rec);corrupt_journal["result"]=gpo::result("awaiting_local_approval","gpo_local_approval_required");
    rejects([&]{gpo::parse_journal(corrupt_journal);});
    corrupt_journal=gpo::journal_document(rec);corrupt_journal["gpo_guid"]="44444444-4444-4444-8444-444444444444";
    rejects([&]{gpo::parse_journal(corrupt_journal);});
    std::vector<std::uint8_t> artifact{'I','P','M','S','G','P','O','1'};append_u32(artifact,1);append_u32(artifact,3);artifact.insert(artifact.end(),{'a','b','c'});
    std::string hash=gpo::sha256(artifact);const std::array<gpo::file_descriptor,1> files{{{"Backup.xml",3,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}};
    gpo::component_descriptor c{"test","","","","machine","test","",hash,static_cast<std::uint32_t>(artifact.size()),1,files,{}};
    require(gpo::decode_artifact(c,artifact).size()==1,"Valid artifact rejected");
    auto corrupt=artifact;corrupt.back()='d';rejects([&]{gpo::decode_artifact(c,corrupt);});
    corrupt=artifact;corrupt.push_back(0);rejects([&]{gpo::decode_artifact(c,corrupt);});
    corrupt=artifact;corrupt[8]=2;hash=gpo::sha256(corrupt);rejects([&]{gpo::decode_artifact(c,corrupt);});
    // Optional offline real-package check; never installs/imports any policy.
    if(argc==2)for(const auto& item:gpo::components){const auto path=std::filesystem::path(argv[1])/(std::string(item.artifact_sha256)+".ipmsgpo");
      std::ifstream input(path,std::ios::binary);require(static_cast<bool>(input),"Pinned artifact missing");
      const std::string bytes((std::istreambuf_iterator<char>(input)),{});
      gpo::decode_artifact(item,{reinterpret_cast<const std::uint8_t*>(bytes.data()),bytes.size()});}
    std::cout<<"GPO contract, hash, artifact and durable write boundary checks passed without AD calls.\n";return 0;
  }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
