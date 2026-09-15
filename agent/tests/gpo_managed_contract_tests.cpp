// File Name: gpo_managed_contract_tests.cpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Managed GPO inspection, stable identity and irreversible boundary regressions without AD.
#include "ipms/agent/gpo_managed.hpp"
#include <iostream>
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>

namespace gpo=ipms::agent::gpo;
namespace json=gpo::json;
namespace {
constexpr const char* id="44444444-4444-4444-8444-444444444444";
constexpr const char* managed="77777777-7777-4777-8777-777777777777";
constexpr const char* uri="spiffe://example.invalid/agent/test";
constexpr const char* dn="OU=Servers,DC=example,DC=invalid";
void require(bool condition,const char* message){if(!condition)throw std::runtime_error(message);}
template<class F>void rejects(F&& fn){bool rejected=false;try{fn();}catch(...){rejected=true;}require(rejected,"Invalid contract accepted");}
json::object snapshot(bool exists=true,bool active=false) {
  json::value g;
  if(exists)g=json::object{{"guid",id},{"name","1-C-ALL-MS-WS2025_V1.0.0"},{"description",std::string("IPMS managed GPO; id=")+managed},
    {"computer_enabled",active},{"user_enabled",false},{"computer_ds",1},{"computer_sysvol",1},{"user_ds",0},{"user_sysvol",0},
    {"security_digest",std::string(64,'a')},{"wmi_filter",""},{"links",json::array{}}};
  return {{"schema",1},{"gpo",g},{"ous",json::array{}},{"name_available",true}};
}
json::object link(std::string value=id,bool enabled=false,long order=1) {
  return {{"guid",value},{"domain","example.invalid"},{"dn",dn},{"kind","ou"},{"enabled",enabled},{"enforced",false},{"order",order}};
}
void target(json::object& state,bool active=false) {
  const auto own=link(id,active);const auto other=link("99999999-9999-4999-8999-999999999999",true,2);
  state["ous"]=json::array{json::object{{"dn",dn},{"guid","88888888-8888-4888-8888-888888888888"},{"usn","123"},{"blocked",false},
    {"links",json::array{own,other}},{"inherited_links",json::array{}}}};
  state.at("gpo").as<json::object>()["links"]=json::array{own};
}
json::object document(std::string op="import_managed_gpo",json::object state=snapshot()) {
  const auto& component=gpo::components.front();const bool read=op=="inspect_managed_gpo";
  const bool exists=!state.at("gpo").get_if<std::nullptr_t>();
  json::array ous,orders;for(const auto& item:state.at("ous").as<json::array>()){ous.push_back(item.as<json::object>().at("dn"));orders.push_back(1);}
  json::object j{{"schema",3},{"job_id","11111111-1111-4111-8111-111111111111"},{"input_digest",""},{"operation",op},
    {"domain_dns_name","example.invalid"},{"domain_guid","22222222-2222-4222-8222-222222222222"},{"forest_dns_name","example.invalid"},
    {"executor_dc_fqdn","dc.example.invalid"},{"scope_id","33333333-3333-4333-8333-333333333333"},{"scope_revision",1},{"target_tier",1},
    {"baseline_id",component.baseline_id},{"profile","server"},{"backup_id",component.backup_id},{"artifact_sha256",component.artifact_sha256},
    {"pilot_display_name","1-C-ALL-MS-WS2025_V2.0.0"},{"expires_at","2030-01-01T00:10:00Z"},{"approval_mode",read?"inspection":"portal"},
    {"managed_id",managed},{"managed_revision",1},{"gpo_guid",exists?id:""},{"owner_marker",exists?state.at("gpo").as<json::object>().at("description").as<std::string>():""},
    {"target_ous",ous},{"link_orders",orders},{"preflight_id",read?"":"66666666-6666-4666-8666-666666666666"},
    {"expected_state",read?json::value{}:json::value(state)},{"intended_operation",read?"import_managed_gpo":op},
    {"safety_review",json::object{{"management_access",op=="activate_managed_gpo"},{"recovery_access",op=="activate_managed_gpo"}}}};
  j["input_digest"]=gpo::input_digest(j);return j;
}
gpo::journal record(json::object doc) {
  gpo::journal j{gpo::parse_job(doc),uri};
  if(gpo::inspection(j.assignment))return j;
  j.state=gpo::phase::granted;j.grant_deadline_tick=1000;
  j.portal_approval=json::object{{"schema",1},{"job_id",j.assignment.text("job_id")},{"input_digest",j.assignment.text("input_digest")},
    {"device_uri",uri},{"domain_guid",j.assignment.text("domain_guid")},{"target_tier",j.assignment.number("target_tier")},{"operation",j.assignment.text("operation")},
    {"requested_by","1"},{"approved_by","1"},{"approved_at","2030-01-01T00:00:00Z"},{"expires_at",j.assignment.text("expires_at")},
    {"policy_revision",1},{"four_eyes_required",false}};return j;
}
class provider final:public gpo::managed_provider {
 public:
  json::object state;std::vector<std::string> calls;std::string failure;std::string failure_code="gpo_provider_failed";int inspections{};bool drift{};bool drift_after_import{};bool partial_link_failure{};
  explicit provider(json::object s):state(std::move(s)){}
  void call(const char* op){calls.emplace_back(op);if(failure==op)throw gpo::operation_error(failure_code);}
  json::object inspect()override{call("inspect");++inspections;if(drift&&inspections==2)state["name_available"]=false;if(drift_after_import&&inspections==3)state.at("ous").as<json::array>()[0].as<json::object>()["usn"]="124";return state;}
  void prepare()override{call("prepare");}
  std::string create()override{call("create");state["gpo"]=snapshot().at("gpo");return id;}
  void initialize(std::string_view)override{call("initialize");state.at("gpo").as<json::object>()["name"]="1-C-ALL-MS-WS2025_V2.0.0";}
  void adopt(std::string_view)override{call("adopt");state.at("gpo").as<json::object>()["description"]=std::string("IPMS managed GPO; id=")+managed;state.at("gpo").as<json::object>()["name"]="1-C-ALL-MS-WS2025_V2.0.0";}
  std::pair<std::string,std::string> backup(std::string_view)override{call("backup");return {"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",std::string(64,'b')};}
  void link(std::string_view)override{
    call("link");json::array own_links;
    for(auto& value:state.at("ous").as<json::array>()) {
      auto& ou=value.as<json::object>();auto& direct=ou.at("links").as<json::array>();
      direct.erase(std::remove_if(direct.begin(),direct.end(),[](const auto& v){return v.template as<json::object>().at("guid").template as<std::string>()==id;}),direct.end());
      auto own=::link(id,false,1);own["dn"]=ou.at("dn");own["kind"]=ou.at("dn").as<std::string>().starts_with("DC=")?"domain":"ou";
      direct.insert(direct.begin(),own);for(std::size_t n=0;n<direct.size();++n)direct[n].as<json::object>()["order"]=n+1;
      own_links.push_back(own);state.at("gpo").as<json::object>()["links"]=own_links;
      if(partial_link_failure)throw gpo::operation_error("gpo_provider_failed");
    }
  }
  void activate(std::string_view)override{call("activate");state.at("gpo").as<json::object>()["computer_enabled"]=gpo::components.front().scope=="machine";state.at("gpo").as<json::object>()["user_enabled"]=gpo::components.front().scope=="user";state.at("gpo").as<json::object>()["name"]="1-C-ALL-MS-WS2025_V2.0.0";}
  void deactivate(std::string_view)override{call("deactivate");state.at("gpo").as<json::object>()["computer_enabled"]=false;state.at("gpo").as<json::object>()["user_enabled"]=false;}
};
void save(const gpo::journal& j) {
  // Exercise the real parser/serializer limits with nested expected/observed
  // links and immutable approval, not only the in-memory object shape.
  const auto restored=gpo::parse_journal(json::parse(json::serialize(gpo::journal_document(j))));
  require(restored.assignment==j.assignment&&restored.result==j.result,"Journal round-trip lost authority/state");
}
}
int main() {
 try {
  const auto now=std::chrono::sys_days(std::chrono::year(2030)/1/1);
  // Architectural regression: the managed provider runs inside a Job Object
  // with ActiveProcessLimit=1. It must consume the worker's direct local read,
  // never invoke the public probe that creates another isolated process.
  const auto source=[](const char* relative) {std::ifstream stream(std::string(IPMS_AGENT_SOURCE_ROOT)+relative);require(stream.good(),"Missing worker-boundary source fixture");return std::string(std::istreambuf_iterator<char>(stream),{});};
  const auto managed_source=source("/src/windows/windows_gpo_managed.cpp");
  for(const auto* nested:{"probe_gpo_executor(","worker_call(","CreateProcess", "invoke_gpo_inspection_worker(","invoke_gpo_pilot_worker("})
    require(managed_source.find(nested)==std::string::npos,"Managed provider attempts forbidden nested process dispatch");
  const auto worker_source=source("/src/windows/windows_gpo_management.cpp");
  const std::string direct_factory="make_managed_gpo_provider(record->assignment,executor_identity())";
  const auto first_factory=worker_source.find(direct_factory);require(first_factory!=std::string::npos&&worker_source.find(direct_factory,first_factory+direct_factory.size())!=std::string::npos,"Inspection and execution workers must supply direct local executor identity");
  require(worker_source.find("limits.BasicLimitInformation.ActiveProcessLimit=1")!=std::string::npos,"GPO worker process isolation was weakened");
  auto d=document();require(gpo::parse_job(d).number("schema")==3,"Schema3 rejected");
  require(gpo::unexpired(gpo::parse_job(d),now),"Valid short job rejected");
  json::object exact_executor{{"role","writable-domain-controller"},{"gpmc_available",true},{"domain_dns_name",d.at("domain_dns_name")},
    {"domain_guid",d.at("domain_guid")},{"forest_dns_name",d.at("forest_dns_name")},{"dc_fqdn",d.at("executor_dc_fqdn")}};
  require(gpo::executor_matches(gpo::parse_job(d),exact_executor),"Exact direct local executor identity rejected");
  for(const auto* key:{"role","domain_dns_name","domain_guid","forest_dns_name","dc_fqdn"}) {auto wrong=exact_executor;wrong[key]="mismatch";require(!gpo::executor_matches(gpo::parse_job(d),wrong),"Direct identity path weakened a binding check");}
  auto no_gpmc=exact_executor;no_gpmc["gpmc_available"]=false;require(!gpo::executor_matches(gpo::parse_job(d),no_gpmc),"Direct identity path ignored GPMC availability");

  auto long_lived=d;long_lived["expires_at"]="2030-01-01T00:20:00Z";long_lived["input_digest"]=gpo::input_digest(long_lived);
  require(!gpo::unexpired(gpo::parse_job(long_lived),now),"Overlong schema3 grant accepted");
  for(const auto* key:{"command","script","destination_path","acl","url"}) {auto bad=d;bad[key]="unexpected";bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});}
  for(const auto* key:{"managed_id","preflight_id","gpo_guid"}){auto bad=d;bad[key]="not-a-guid";bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});}
  auto bad=d;bad["gpo_guid"]="31b2f340-016d-11d2-945f-00c04fb984f9";bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
  bad=d;bad["owner_marker"]="Some administrator's policy";bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
  bad=d;bad["managed_revision"]=true;bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
  bad=d;bad.at("expected_state").as<json::object>()["unknown"]=false;bad["input_digest"]=gpo::input_digest(bad);rejects([&]{gpo::parse_job(bad);});
  auto inspected=record(document("inspect_managed_gpo",snapshot(false)));provider reader(snapshot(false));
  const auto inspection=gpo::inspect_managed(inspected,reader,save,[]{return true;});
  require(inspection.at("status").as<std::string>()=="inspected"&&reader.calls==std::vector<std::string>{"inspect"},"Inspection reached write/artifact provider");
  auto read_job=record(document("inspect_managed_gpo"));provider never(snapshot());rejects([&]{gpo::execute_managed(read_job,never,save,[]{return true;},[]{});});require(never.calls.empty(),"Inspection entered write path");
  auto j=record(document("import_managed_gpo",snapshot(false)));provider first(snapshot(false));std::vector<gpo::phase> phases;
  const auto result=gpo::execute_managed(j,first,[&](const auto& item){save(item);phases.push_back(item.state);},[]{return true;},[]{});
  require(result.at("status").as<std::string>()=="staged"&&first.calls==std::vector<std::string>{"inspect","prepare","inspect","create","initialize","inspect"},"Initial import lifecycle changed");
  require(phases==std::vector<gpo::phase>{gpo::phase::creating,gpo::phase::created,gpo::phase::importing,gpo::phase::terminal},"Write lacks durable preceding intent");
  j=record(document("import_managed_gpo",snapshot(true,true)));provider update(snapshot(true,true));const auto previous=update.state;
  const auto prepared=gpo::execute_managed(j,update,save,[]{return true;},[]{});
  require(prepared.at("status").as<std::string>()=="staged"&&update.state==previous&&update.calls==std::vector<std::string>{"inspect","prepare","inspect"},"Import changed active stable GPO");
  auto linked_state=snapshot(true,true);target(linked_state,true);j=record(document("deactivate_managed_gpo",linked_state));provider inactive(linked_state);
  require(gpo::execute_managed(j,inactive,save,[]{return true;},[]{}).at("status").as<std::string>()=="deactivated","Deactivation failed");
  const auto unrelated=inactive.state.at("ous").as<json::array>()[0].as<json::object>().at("links").as<json::array>()[1];
  j=record(document("link_managed_gpo",inactive.state));provider relink(inactive.state);
  require(gpo::execute_managed(j,relink,save,[]{return true;},[]{}).at("status").as<std::string>()=="linked","Disabled GPO cannot edit previously enabled own link");
  require(relink.state.at("ous").as<json::array>()[0].as<json::object>().at("links").as<json::array>()[1]==unrelated,"Relink changed unrelated sibling");
  j=record(document("link_managed_gpo",linked_state));provider active_link(linked_state);
  require(gpo::execute_managed(j,active_link,save,[]{return true;},[]{}).at("result_code").as<std::string>()=="gpo_requires_disabled"&&active_link.calls.size()==1,"Active GPO reached link mutation");
  j=record(document("activate_managed_gpo",linked_state));provider activate(linked_state);
  require(gpo::execute_managed(j,activate,save,[]{return true;},[]{}).at("status").as<std::string>()=="activated","Activation failed");
  require(activate.calls==std::vector<std::string>{"inspect","prepare","backup","inspect","activate","inspect"},"Activation precedes protected recovery backup");
  const auto calls=activate.calls;gpo::execute_managed(j,activate,save,[]{return true;},[]{});require(calls==activate.calls,"Receipt replay wrote AD again");
  for(const auto* failure:{"inspect","prepare","backup","activate"}) {
    j=record(document("activate_managed_gpo",linked_state));provider broken(linked_state);broken.failure=failure;
    const auto r=gpo::execute_managed(j,broken,save,[]{return true;},[]{});
    require(r.at("status").as<std::string>()==(std::string(failure)=="activate"?"requires_reconciliation":"failed"),"Wrong failure recovery fence");
  }
  j=record(document());provider stale(snapshot());stale.drift=true;
  require(gpo::execute_managed(j,stale,save,[]{return true;},[]{}).at("result_code").as<std::string>()=="gpo_state_changed"&&stale.calls.size()==3,"Drift reached mutation");
  j=record(document("import_managed_gpo",snapshot(false)));provider disk(snapshot(false));
  rejects([&]{gpo::execute_managed(j,disk,[](const auto&){throw std::runtime_error("disk");},[]{return true;},[]{});});
  require(std::find(disk.calls.begin(),disk.calls.end(),"create")==disk.calls.end(),"Disk failure allowed creation");
  auto adoption=snapshot();adoption.at("gpo").as<json::object>()["description"]=std::string("IPMS disabled, unlinked pilot; job=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa; digest=")+std::string(64,'b');
  j=record(document("import_managed_gpo",adoption));provider adopted(adoption);
  require(gpo::execute_managed(j,adopted,save,[]{return true;},[]{}).at("status").as<std::string>()=="staged"&&j.gpo_guid==id,"Exact legacy adoption lost stable GUID");
  auto unsafe=linked_state;unsafe.at("gpo").as<json::object>().at("links").as<json::array>()[0].as<json::object>()["enforced"]=true;
  j=record(document("activate_managed_gpo",unsafe));provider enforced(unsafe);
  require(gpo::execute_managed(j,enforced,save,[]{return true;},[]{}).at("result_code").as<std::string>()=="gpo_link_conflict","Enforced own link activated");
  auto second=linked_state;
  auto& second_direct=second.at("ous").as<json::array>()[0].as<json::object>().at("links").as<json::array>();
  second_direct[0].as<json::object>()["order"]=2;second_direct[1].as<json::object>()["order"]=1;std::reverse(second_direct.begin(),second_direct.end());
  second.at("gpo").as<json::object>().at("links").as<json::array>()[0].as<json::object>()["order"]=2;
  auto inspect_second=document("inspect_managed_gpo",second);inspect_second["intended_operation"]="activate_managed_gpo";inspect_second["input_digest"]=gpo::input_digest(inspect_second);
  j=record(inspect_second);provider actual_order(second);
  require(gpo::inspect_managed(j,actual_order,save,[]{return true;}).at("status").as<std::string>()=="inspected","Inspection compared unknown link-order placeholder against real AD");
  auto activate_second=document("activate_managed_gpo",second);activate_second["link_orders"]=json::array{2};activate_second["input_digest"]=gpo::input_digest(activate_second);
  j=record(activate_second);provider approved_order(second);
  require(gpo::execute_managed(j,approved_order,save,[]{return true;},[]{}).at("status").as<std::string>()=="activated","Approved second-priority link rejected");
  // A complete multi-domain forest census is required, not a successful
  // security-trimmed local query. Hidden/unavailable locations stop all writes.
  const auto census_job=gpo::parse_job(document());
  const std::vector<gpo::forest_domain> forest{{"example.invalid",census_job.text("domain_guid"),true},
    {"child.example.invalid","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",false}};
  gpo::validate_forest_domains(census_job,forest);
  auto broken_forest=forest;broken_forest[0].primary=false;rejects([&]{gpo::validate_forest_domains(census_job,broken_forest);});
  broken_forest=forest;broken_forest[0].guid=broken_forest[1].guid;rejects([&]{gpo::validate_forest_domains(census_job,broken_forest);});
  broken_forest=forest;broken_forest[1].dns_name=broken_forest[0].dns_name;rejects([&]{gpo::validate_forest_domains(census_job,broken_forest);});
  auto child_job=census_job;child_job.fields["domain_dns_name"]="child.example.invalid";child_job.fields["domain_guid"]=forest[1].guid;
  broken_forest={forest[1]};broken_forest[0].primary=true;rejects([&]{gpo::validate_forest_domains(child_job,broken_forest);});
  broken_forest.assign(33,forest[0]);rejects([&]{gpo::validate_forest_domains(census_job,broken_forest);});
  const std::string policy="CN={44444444-4444-4444-8444-444444444444},CN=Policies,CN=System,DC=example,DC=invalid";
  for(unsigned flags=0;flags<4;++flags)require(gpo::matching_gpo_link("[LDAP://"+policy+";"+std::to_string(flags)+"]",policy)==flags,"gPLink flags lost");
  require(!gpo::matching_gpo_link("[LDAP://CN=Other,"+policy+";0]",policy),"Substring adopted as exact GPO identity");
  rejects([&]{gpo::matching_gpo_link("[LDAP://"+policy+";4]",policy);});
  rejects([&]{gpo::matching_gpo_link("[LDAP://"+policy+";0][LDAP://"+policy+";1]",policy);});
  rejects([&]{gpo::matching_gpo_link("[LDAP://"+policy+";0",policy);});
  std::map<std::string,std::uint32_t> complete{{"ou=servers,dc=example,dc=invalid",0}};
  gpo::verify_forest_link_census(json::array{link(id,true)},complete);
  complete["ou=foreign,dc=child,dc=example,dc=invalid"]=0;
  rejects([&]{gpo::verify_forest_link_census(json::array{link(id,true)},complete);});
  auto foreign=link(id,true);foreign["dn"]="OU=Foreign,DC=child,DC=example,DC=invalid";
  gpo::verify_forest_link_census(json::array{link(id,true),foreign},complete);
  auto foreign_state=linked_state;foreign_state.at("gpo").as<json::object>().at("links").as<json::array>().push_back(foreign);
  for(const auto* op:{"activate_managed_gpo","deactivate_managed_gpo","link_managed_gpo"}) {
    auto blocked_state=foreign_state;if(std::string(op)=="link_managed_gpo")blocked_state.at("gpo").as<json::object>()["computer_enabled"]=false;
    j=record(document(op,blocked_state));provider foreign_provider(blocked_state);
    require(gpo::execute_managed(j,foreign_provider,save,[]{return true;},[]{}).at("result_code").as<std::string>()=="gpo_link_conflict"&&foreign_provider.calls.size()==1,"Foreign-domain link reached mutation");
  }
  j=record(document("activate_managed_gpo",linked_state));provider incomplete(linked_state);incomplete.failure="inspect";incomplete.failure_code="gpo_preflight_required";
  require(gpo::execute_managed(j,incomplete,save,[]{return true;},[]{}).at("result_code").as<std::string>()=="gpo_preflight_required"&&incomplete.calls.size()==1,"Incomplete forest visibility reached mutation");
  auto case_document=document("activate_managed_gpo",linked_state);case_document["target_ous"]=json::array{"ou=servers,dc=example,dc=invalid"};case_document["input_digest"]=gpo::input_digest(case_document);
  j=record(case_document);provider case_provider(linked_state);require(gpo::execute_managed(j,case_provider,save,[]{return true;},[]{}).at("status").as<std::string>()=="activated","AD DN capitalization rejected equivalent configured target");
  const auto domain_component=std::find_if(gpo::components.begin(),gpo::components.end(),[](const auto& c){return c.scope=="domain";});
  require(domain_component!=gpo::components.end(),"Missing domain-scope negative fixture");
  const auto domain_document=[&](const char* op,json::object state) {
    auto doc=document(op,state);doc["baseline_id"]=domain_component->baseline_id;doc["backup_id"]=domain_component->backup_id;
    doc["artifact_sha256"]=domain_component->artifact_sha256;doc["target_tier"]=0;
    doc["target_ous"]=state.at("ous").as<json::array>().empty()?json::array{}:json::array{"DC=example,DC=invalid"};
    doc["input_digest"]=gpo::input_digest(doc);return doc;
  };
  auto root_state=linked_state;root_state.at("gpo").as<json::object>()["computer_enabled"]=false;
  auto& root_target=root_state.at("ous").as<json::array>()[0].as<json::object>();root_target["dn"]="DC=example,DC=invalid";root_target["guid"]=census_job.text("domain_guid");
  for(auto& value:root_target.at("links").as<json::array>()){value.as<json::object>()["dn"]="DC=example,DC=invalid";value.as<json::object>()["kind"]="domain";}
  for(auto& value:root_state.at("gpo").as<json::object>().at("links").as<json::array>()){value.as<json::object>()["dn"]="DC=example,DC=invalid";value.as<json::object>()["kind"]="domain";}
  for(const auto* op:{"link_managed_gpo","activate_managed_gpo","deactivate_managed_gpo"}) {
    auto doc=domain_document(op,root_state);auto wrong_tier=doc;wrong_tier["target_tier"]=1;wrong_tier["input_digest"]=gpo::input_digest(wrong_tier);rejects([&]{gpo::parse_job(wrong_tier);});
    auto wrong_target=doc;wrong_target["target_ous"]=json::array{dn};wrong_target["input_digest"]=gpo::input_digest(wrong_target);rejects([&]{gpo::parse_job(wrong_target);});
    j=record(doc);provider root_provider(root_state);
    const auto result=gpo::execute_managed(j,root_provider,save,[]{return true;},[]{});
    require(result.at("status").as<std::string>()==(std::string(op)=="link_managed_gpo"?"linked":std::string(op)=="activate_managed_gpo"?"activated":"deactivated"),"Explicit Tier0 domain root operation failed");
  }
  auto wrong_identity=root_state;wrong_identity.at("ous").as<json::array>()[0].as<json::object>()["guid"]="88888888-8888-4888-8888-888888888888";
  j=record(domain_document("activate_managed_gpo",wrong_identity));provider wrong_root(wrong_identity);
  require(gpo::execute_managed(j,wrong_root,save,[]{return true;},[]{}).at("result_code").as<std::string>()=="gpo_target_invalid"&&wrong_root.calls.size()==1,"Wrong domain root GUID reached mutation");
  auto domain_import=domain_document("import_managed_gpo",snapshot(false));require(gpo::parse_job(domain_import).fields.at("target_ous").as<json::array>().empty(),"Domain import requires root link prematurely");
  auto unexpected_root=document("activate_managed_gpo",root_state);unexpected_root["target_ous"]=json::array{"DC=example,DC=invalid"};unexpected_root["input_digest"]=gpo::input_digest(unexpected_root);
  rejects([&]{gpo::parse_job(unexpected_root);});
  // Combined import/link has one claim and never enables policy content.
  const auto unlinked_targets=[](json::object state,bool exists) {
    for(auto& item:state.at("ous").as<json::array>()) {
      auto& links=item.as<json::object>().at("links").as<json::array>();
      links.erase(std::remove_if(links.begin(),links.end(),[](const auto& v){return v.template as<json::object>().at("guid").template as<std::string>()==id;}),links.end());
      for(std::size_t n=0;n<links.size();++n)links[n].as<json::object>()["order"]=n+1;
    }
    if(!exists)state["gpo"]=json::value{};
    else {auto& policy=state.at("gpo").as<json::object>();policy["computer_enabled"]=false;policy["user_enabled"]=false;policy["links"]=json::array{};}
    return state;
  };
  auto combined_before=unlinked_targets(linked_state,false);
  auto combined_inspection=document("inspect_managed_gpo",combined_before);combined_inspection["intended_operation"]="import_and_link_managed_gpo";combined_inspection["input_digest"]=gpo::input_digest(combined_inspection);
  j=record(combined_inspection);provider combined_reader(combined_before);
  require(gpo::inspect_managed(j,combined_reader,save,[]{return true;}).at("status").as<std::string>()=="inspected"&&combined_reader.calls==std::vector<std::string>{"inspect"},"Combined inspection acquired write authority");
  j=record(document("import_and_link_managed_gpo",combined_before));provider combined(combined_before);unsigned claims{};
  const auto combined_result=gpo::execute_managed(j,combined,save,[]{return true;},[&]{++claims;});
  require(combined_result.at("status").as<std::string>()=="linked"&&claims==1&&j.gpo_guid==id,"Combined initial OU operation failed or consumed multiple claims");
  require(combined.calls==std::vector<std::string>{"inspect","prepare","inspect","create","initialize","inspect","link","inspect"},"Combined operation does not reread between import and link");
  const auto combined_calls=combined.calls;gpo::execute_managed(j,combined,save,[]{return true;},[&]{++claims;});
  require(combined.calls==combined_calls&&claims==1,"Combined successful receipt replayed a write");
  require(!combined.state.at("gpo").as<json::object>().at("computer_enabled").as<bool>()&&!combined.state.at("gpo").as<json::object>().at("user_enabled").as<bool>(),"Combined operation activated policy");
  auto wrong_artifact=gpo::journal_document(j);wrong_artifact.at("result").as<json::object>().at("evidence").as<json::object>()["prepared_artifact_sha256"]=std::string(64,'e');
  rejects([&]{gpo::parse_journal(wrong_artifact);});
  for(const auto* failure:{"initialize","link"}) {
    j=record(document("import_and_link_managed_gpo",combined_before));provider interrupted(combined_before);interrupted.failure=failure;
    const auto failed=gpo::execute_managed(j,interrupted,save,[]{return true;},[]{});
    require(failed.at("status").as<std::string>()=="requires_reconciliation"&&failed.at("gpo_guid").as<std::string>()==id,"Partial combined import lost exact GUID or retry fence");
    const auto calls=interrupted.calls;gpo::execute_managed(j,interrupted,save,[]{return true;},[]{});require(interrupted.calls==calls,"Partial combined result retried creation or linking");
  }
  j=record(document("import_and_link_managed_gpo",combined_before));provider drift_between(combined_before);drift_between.drift_after_import=true;
  require(gpo::execute_managed(j,drift_between,save,[]{return true;},[]{}).at("result_code").as<std::string>()=="gpo_state_changed"&&
    std::find(drift_between.calls.begin(),drift_between.calls.end(),"link")==drift_between.calls.end()&&j.gpo_guid==id,"Target drift after import reached linking");
  j=record(document("import_and_link_managed_gpo",combined_before));provider expired_between(combined_before);
  require(gpo::execute_managed(j,expired_between,save,[&]{return expired_between.inspections<3;},[]{}).at("result_code").as<std::string>()=="gpo_authority_expired"&&j.gpo_guid==id&&
    std::find(expired_between.calls.begin(),expired_between.calls.end(),"link")==expired_between.calls.end(),"Expired whole-operation grant permitted linking after import");
  auto multiple_targets=combined_before;auto extra_target=multiple_targets.at("ous").as<json::array>()[0].as<json::object>();
  extra_target["dn"]="OU=Additional,DC=example,DC=invalid";extra_target["guid"]="abababab-abab-4bab-8bab-abababababab";
  for(auto& value:extra_target.at("links").as<json::array>())value.as<json::object>()["dn"]=extra_target.at("dn");
  multiple_targets.at("ous").as<json::array>().push_back(extra_target);
  j=record(document("import_and_link_managed_gpo",multiple_targets));provider partial_link(multiple_targets);partial_link.partial_link_failure=true;
  require(gpo::execute_managed(j,partial_link,save,[]{return true;},[]{}).at("status").as<std::string>()=="requires_reconciliation"&&j.gpo_guid==id&&
    partial_link.state.at("gpo").as<json::object>().at("links").as<json::array>().size()==1&&partial_link.state.at("ous").as<json::array>().size()==2,"Partial link effect was reported as success or lost identity");
  auto combined_existing=unlinked_targets(linked_state,true);j=record(document("import_and_link_managed_gpo",combined_existing));provider existing_combined(combined_existing);
  require(gpo::execute_managed(j,existing_combined,save,[]{return true;},[]{}).at("status").as<std::string>()=="linked","Existing disabled GPO preparation/link failed");
  require(existing_combined.state.at("gpo").as<json::object>().at("name")==combined_existing.at("gpo").as<json::object>().at("name")&&
    std::find(existing_combined.calls.begin(),existing_combined.calls.end(),"initialize")==existing_combined.calls.end(),"Combined preparation applied new content/name before activation");
  j=record(document("import_and_link_managed_gpo",linked_state));provider active_combined(linked_state);
  require(gpo::execute_managed(j,active_combined,save,[]{return true;},[]{}).at("result_code").as<std::string>()=="gpo_requires_disabled"&&active_combined.calls.size()==1,"Combined operation changed active policy");
  auto combined_adoption=combined_existing;combined_adoption.at("gpo").as<json::object>()["description"]=adoption.at("gpo").as<json::object>().at("description");
  j=record(document("import_and_link_managed_gpo",combined_adoption));provider adopted_combined(combined_adoption);
  require(gpo::execute_managed(j,adopted_combined,save,[]{return true;},[]{}).at("status").as<std::string>()=="linked"&&j.gpo_guid==id&&
    std::find(adopted_combined.calls.begin(),adopted_combined.calls.end(),"create")==adopted_combined.calls.end(),"Exact legacy adoption duplicated GPO during combined operation");
  auto combined_root=unlinked_targets(root_state,false);j=record(domain_document("import_and_link_managed_gpo",combined_root));provider root_combined(combined_root);
  require(gpo::execute_managed(j,root_combined,save,[]{return true;},[]{}).at("status").as<std::string>()=="linked"&&
    root_combined.state.at("gpo").as<json::object>().at("links").as<json::array>()[0].as<json::object>().at("kind").as<std::string>()=="domain","Combined Tier0 domain root operation failed");
  auto wrong_combined_tier=domain_document("import_and_link_managed_gpo",combined_root);wrong_combined_tier["target_tier"]=1;wrong_combined_tier["input_digest"]=gpo::input_digest(wrong_combined_tier);rejects([&]{gpo::parse_job(wrong_combined_tier);});
  auto no_combined_targets=document("import_and_link_managed_gpo",snapshot(false));rejects([&]{gpo::parse_job(no_combined_targets);});
  auto large=snapshot(true,true);target(large,true);
  auto& many=large.at("ous").as<json::array>()[0].as<json::object>().at("links").as<json::array>();
  for(long n=3;n<=128;++n) {
    char unique[37]{};std::snprintf(unique,sizeof(unique),"aaaaaaaa-aaaa-4aaa-8aaa-%012ld",n);
    many.push_back(link(unique,true,n));
    if(json::serialize(large).size()>16384) {many.pop_back();break;}
  }
  const auto snapshot_bytes=json::serialize(large).size();require(snapshot_bytes>16000&&gpo::valid_snapshot(large),"Near-boundary snapshot fixture is too small");
  j=record(document("import_managed_gpo",large));provider large_provider(large);
  require(gpo::execute_managed(j,large_provider,save,[]{return true;},[]{}).at("status").as<std::string>()=="staged","Valid large journal cannot round-trip");
  const auto journal_bytes=json::serialize(gpo::journal_document(j)).size();require(journal_bytes<65536,"Journal exceeds transport bounds");
  many.push_back(link("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",true,128));require(!gpo::valid_snapshot(large),"Oversized snapshot accepted");
  std::cout<<"Boundary fixture: snapshot="<<snapshot_bytes<<" bytes; complete journal="<<journal_bytes<<" bytes.\n";
  std::cout<<"Managed GPO contract, inspection, stable update, approval and durable mutation boundaries passed without AD.\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
