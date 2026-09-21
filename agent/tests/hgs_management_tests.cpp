// File Name: hgs_management_tests.cpp
// Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-20
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Hostile schemas, durable intent ordering, lost replies and reboot recovery without live HGS.
#include "ipms/agent/hgs_management.hpp"
#include <iostream>
#include <vector>
namespace hgs=ipms::agent::hgs;
namespace json=hgs::json;
namespace {
void require(bool v,const char* message){if(!v)throw std::runtime_error(message);}
template<class F> void rejects(F fn){bool rejected=false;try{fn();}catch(...){rejected=true;}require(rejected,"Unsafe HGS schema accepted");}
json::object config(){return {{"profile","shielded"},{"attestation_mode","tpm"},{"domain_name","hgs.example.invalid"},{"service_name","guardians"},
 {"feature_source","D:\\sources\\sxs"},{"signing_thumbprint",std::string(40,'A')},{"encryption_thumbprint",std::string(40,'B')},
 {"dsrm_secret_ref","hgs_dsrm"},{"join_secret_ref",""},{"allow_reboot",true},{"node_role","primary"},{"primary_server",""}};}
hgs::job assignment(const char* op="install_role") {return hgs::parse_job(json::object{{"schema_version",1},{"job_id","11111111-1111-4111-8111-111111111111"},
 {"deployment_id","22222222-2222-4222-8222-222222222222"},{"tenant_id","33333333-3333-4333-8333-333333333333"},{"enrollment_id","44444444-4444-4444-8444-444444444444"},
 {"device_uri","urn:ipms:agent:55555555-5555-4555-8555-555555555555"},{"plan_digest",std::string(64,'a')},{"operation",op},{"config",config()},{"expires_at",4102444800LL}});}
json::object observation(){return {{"os_build","26100"},{"is_server",true},{"computer_name","HGS01"},{"domain_name",""},{"domain_joined",false},{"domain_role",2},
 {"role_installed",false},{"service_initialized",false},{"attestation_mode","none"},{"signing_certificate_ready",true},{"encryption_certificate_ready",true},
 {"feature_source_ready",true},{"dsrm_secret_ready",true},{"join_secret_ready",false},{"reboot_pending",false},{"boot_id","2026-09-19T10:00:00.0000000Z"},
 {"service_healthy",false},{"key_access_verified",true},{"mode_supported",true},{"offline_source_policy_ready",true},
 {"configured_service_name",""},{"configured_signing_thumbprint",""},{"configured_encryption_thumbprint",""}};}
struct fake_provider:hgs::provider {
 json::object current=observation();unsigned writes=0,reads=0;bool fail_after_write=false;std::function<void()> before_apply=[]{};
 json::object inspect(const hgs::job&)override{++reads;return current;}
 void apply(const hgs::job& j)override{
   before_apply();++writes;if(j.text("operation")=="install_role")current["role_installed"]=true;
   if(fail_after_write)throw std::runtime_error("simulated connection loss");
 }
};
}
int main(){try {
 const auto valid=assignment();require(hgs::bound_to(valid,valid.text("device_uri")),"Device identity not bound");require(!hgs::bound_to(valid,"other"),"Foreign device accepted");
 auto f=valid.fields;f["script"]="Write-Host test";rejects([&]{hgs::parse_job(f);});
 f=valid.fields;f["operation"]="shell";rejects([&]{hgs::parse_job(f);});
 f=valid.fields;f["expires_at"]="4102444800";rejects([&]{hgs::parse_job(f);});
 for(const auto path:{"https://example.invalid/source","\\\\server\\share","D:\\source\\..\\evil","D:\\source\";run","D:\\source:stream","D:\\source$(run)"}){
   f=valid.fields;f.at("config").as<json::object>()["feature_source"]=path;rejects([&]{hgs::parse_job(f);});}
 f=valid.fields;f.at("config").as<json::object>()["attestation_mode"]="host_key";rejects([&]{hgs::parse_job(f);});
 f.at("config").as<json::object>()["profile"]="vtpm";require(hgs::parse_job(f).config().at("attestation_mode").as<std::string>()=="host_key","Simple mode unavailable");
 f=valid.fields;f.at("config").as<json::object>()["dsrm_secret_ref"]="..\\secret";rejects([&]{hgs::parse_job(f);});
 f=valid.fields;f.at("config").as<json::object>()["password"]="forbidden";rejects([&]{hgs::parse_job(f);});
 std::vector<hgs::journal> persisted;const auto save=[&](const hgs::journal& j){persisted.push_back(hgs::parse_journal(hgs::journal_document(j)));};
 fake_provider provider;hgs::journal record{valid};unsigned claims=0;
 provider.before_apply=[&]{require(!persisted.empty()&&persisted.back().state==hgs::phase::intent,"Write before durable intent");require(claims==1,"Write before exact claim");};
 auto out=hgs::execute(record,provider,save,[&]{++claims;return true;},[]{return true;});
 require(provider.writes==1&&out.at("status").as<std::string>()=="succeeded","Role step failed");
 hgs::execute(record,provider,save,[]{throw std::runtime_error("must not claim twice");return false;},[]{return true;});
 require(provider.writes==1&&claims==1,"Terminal replay performed another write");
 fake_provider revoked;bool authority=true;hgs::journal revoke_during_flush{valid};
 const auto withdrawing_save=[&](const hgs::journal& j){save(j);if(j.state==hgs::phase::intent)authority=false;};
 hgs::execute(revoke_during_flush,revoked,withdrawing_save,[]{return true;},[&]{return authority;});
 require(revoked.writes==0&&revoke_during_flush.outcome.at("status").as<std::string>()=="failed","Authority changed during intent flush but mutation ran");
 fake_provider interrupted;hgs::journal lost{valid};
 hgs::journal prepared{valid};hgs::recover(prepared,interrupted,save);
 require(prepared.state==hgs::phase::terminal&&prepared.outcome.at("result_code").as<std::string>()=="hgs_authority_lost"&&interrupted.reads==0&&interrupted.writes==0,"Recovered unclaimed intent blocked replacement work or touched the provider");
 hgs::execute(prepared,interrupted,save,[]{throw std::runtime_error("retired preparation must not claim");return false;},[]{return true;});
 require(interrupted.writes==0,"Retired preparation re-executed");
 auto expired_preparation=valid;expired_preparation.fields["expires_at"]=1;hgs::journal prepared_expired{expired_preparation};hgs::recover(prepared_expired,interrupted,save);
 require(prepared_expired.outcome.at("result_code").as<std::string>()=="hgs_job_expired"&&interrupted.reads==0,"Expired preparation was not retired before polling");
 auto lost_claim=hgs::execute(lost,interrupted,save,[]{throw std::runtime_error("lost claim response");return false;},[]{return true;});
 require(interrupted.writes==0&&lost_claim.at("status").as<std::string>()=="failed"&&lost_claim.at("result_code").as<std::string>()=="hgs_authority_lost","Lost claim was replayable or falsely reported a write");
 hgs::journal claiming{valid,hgs::phase::claiming,observation()};hgs::recover(claiming,interrupted,save);
 require(claiming.outcome.at("status").as<std::string>()=="failed"&&interrupted.writes==0,"Interrupted claim invented write intent");
 auto inspection=assignment("inspect");hgs::journal interrupted_inspect{inspection,hgs::phase::intent,observation()};
 struct failed_reader:fake_provider { json::object inspect(const hgs::job&)override{throw std::runtime_error("read failed");} } unavailable;
 hgs::recover(interrupted_inspect,unavailable,save);require(interrupted_inspect.outcome.at("status").as<std::string>()=="failed","Read-only reconciliation inspection created a second write fence");
 fake_provider pending_inspector;pending_inspector.current["reboot_pending"]=true;
 hgs::journal pending_inspect{inspection,hgs::phase::intent,observation()};hgs::recover(pending_inspect,pending_inspector,save);
 require(pending_inspect.outcome.at("status").as<std::string>()=="succeeded"&&pending_inspect.outcome.at("result_code").as<std::string>()=="hgs_inspected"&&pending_inspector.writes==0,"Recovered read-only inspection emitted a write/reboot receipt");
 hgs::journal after_crash{valid,hgs::phase::intent,observation()};interrupted.current["role_installed"]=true;
 auto recovered=hgs::recover(after_crash,interrupted,save);require(interrupted.writes==0&&recovered.at("status").as<std::string>()=="succeeded","Postcondition recovery repeated write");
 hgs::journal unknown{valid,hgs::phase::intent,observation()};interrupted.current=observation();hgs::recover(unknown,interrupted,save);
 require(unknown.outcome.at("status").as<std::string>()=="reconciliation_required"&&interrupted.writes==0,"Unproven interrupted step retried");
 json::object release{{"job_id",valid.text("job_id")},{"plan_digest",valid.text("plan_digest")}};
 require(hgs::release_matches(unknown,release),"Exact reconciliation release rejected");
 release["plan_digest"]=std::string(64,'b');require(!hgs::release_matches(unknown,release),"Changed-plan release unfreezes write fence");
 release["plan_digest"]=valid.text("plan_digest");release["job_id"]="77777777-7777-4777-8777-777777777777";require(!hgs::release_matches(unknown,release),"Historical release unfreezes different fence");
 require(hgs::permitted_while_fenced(unknown,assignment("inspect")),"Fresh same-identity inspection blocked");
 require(!hgs::permitted_while_fenced(unknown,assignment("install_role")),"New write offered through reconciliation fence");
 auto other=assignment("inspect");other.fields["tenant_id"]="88888888-8888-4888-8888-888888888888";
 require(!hgs::permitted_while_fenced(unknown,other),"Inspection crossed tenant fence");
 fake_provider joined;joined.current["domain_joined"]=true;joined.current["domain_name"]="fabric.example.invalid";
 hgs::journal reject_domain{valid};hgs::execute(reject_domain,joined,save,[]{return true;},[]{return true;});require(joined.writes==0,"Existing domain was silently repurposed");
 fake_provider expired;auto expired_job=valid;expired_job.fields["expires_at"]=1;hgs::journal old{expired_job};hgs::execute(old,expired,save,[]{return true;},[]{return true;});require(expired.writes==0&&expired.reads==0,"Expired authority inspected or wrote");
 fake_provider rebooter;rebooter.current["reboot_pending"]=true;hgs::journal reboot{assignment("reboot")};
 hgs::execute(reboot,rebooter,save,[]{return true;},[]{return true;});require(reboot.state==hgs::phase::reboot_wait&&rebooter.writes==1,"Reboot did not persist waiting state");
 hgs::recover(reboot,rebooter,save);require(reboot.state==hgs::phase::reboot_wait&&rebooter.writes==1,"Same boot repeated reboot or advanced");
 rebooter.current["boot_id"]="2026-09-19T11:00:00.0000000Z";rebooter.current["reboot_pending"]=false;hgs::recover(reboot,rebooter,save);
 require(reboot.state==hgs::phase::terminal&&reboot.outcome.at("result_code").as<std::string>()=="hgs_reboot_observed"&&rebooter.writes==1,"New boot not proven");
 fake_provider healthy;auto& o=healthy.current;o["domain_joined"]=true;o["domain_name"]="hgs.example.invalid";o["domain_role"]=5;o["role_installed"]=true;o["service_initialized"]=true;o["attestation_mode"]="tpm";
 o["configured_service_name"]="guardians";o["configured_signing_thumbprint"]=std::string(40,'A');o["configured_encryption_thumbprint"]=std::string(40,'B');
 hgs::journal verify{assignment("verify")};hgs::execute(verify,healthy,save,[]{return true;},[]{return true;});require(verify.outcome.at("status").as<std::string>()=="failed","Dead service accepted as verified");
 o["service_healthy"]=true;hgs::journal verify_ok{assignment("verify")};hgs::execute(verify_ok,healthy,save,[]{return true;},[]{return true;});require(verify_ok.outcome.at("status").as<std::string>()=="succeeded"&&healthy.writes==0,"Read-only verification mutated state");
 fake_provider initializing;initializing.current=o;initializing.current["service_initialized"]=false;
 initializing.before_apply=[&]{initializing.current["service_initialized"]=true;initializing.current["reboot_pending"]=true;};
 hgs::journal pending_initialize{assignment("initialize")};hgs::execute(pending_initialize,initializing,save,[]{return true;},[]{return true;});
 require(pending_initialize.outcome.at("status").as<std::string>()=="reconciliation_required"&&initializing.writes==1,"Initialize emitted an unsupported reboot receipt");
 hgs::journal recovered_initialize{assignment("initialize"),hgs::phase::intent,o};hgs::recover(recovered_initialize,initializing,save);
 require(recovered_initialize.outcome.at("status").as<std::string>()=="reconciliation_required"&&initializing.writes==1,"Initialize recovery emitted an unsupported reboot receipt");
 o["attestation_mode"]="host_key";hgs::journal downgrade{assignment("initialize")};hgs::execute(downgrade,healthy,save,[]{return true;},[]{return true;});require(healthy.writes==0,"Attestation mode silently changed");
 o["attestation_mode"]="tpm";o["configured_encryption_thumbprint"]=std::string(40,'C');
 require(!hgs::postcondition(assignment("initialize"),{},o),"Unrelated configured HGS key accepted");
 o["configured_encryption_thumbprint"]=std::string(40,'B');o["configured_service_name"]="another";
 require(!hgs::postcondition(assignment("initialize"),{},o),"Unrelated HGS service accepted");
 o["configured_service_name"]="guardians";o["domain_role"]=3;
 require(!hgs::postcondition(assignment("initialize"),{},o),"HGS initialization accepted a non-DC final state");
 fake_provider promoting;promoting.current["role_installed"]=true;promoting.before_apply=[&]{promoting.current["reboot_pending"]=true;};hgs::journal promote{assignment("create_forest")};
 hgs::execute(promote,promoting,save,[]{return true;},[]{return true;});require(promote.outcome.at("status").as<std::string>()=="reboot_required"&&promoting.writes==1,"Successful staged promotion required final preboot DC identity");
 struct staged_role_provider:fake_provider { void apply(const hgs::job&)override{++writes;current["reboot_pending"]=true;} } staged_role;
 hgs::journal staged_role_record{assignment("install_role")};hgs::execute(staged_role_record,staged_role,save,[]{return true;},[]{return true;});
 require(staged_role_record.outcome.at("status").as<std::string>()=="reboot_required"&&staged_role.writes==1,"Successful staged role installation required final preboot feature state");
 std::cout<<"HGS schema, authority, durable intent, lost response, profile and reboot tests passed.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
