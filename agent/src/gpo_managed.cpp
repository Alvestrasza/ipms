// File Name: gpo_managed.cpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Exact managed-GPO contracts, inspection isolation and durable write ordering.
#include "ipms/agent/gpo_managed.hpp"
#include <algorithm>
#include <set>

namespace ipms::agent::gpo {
namespace {
[[noreturn]] void fail(const char* code="gpo_invalid_job") { throw operation_error(code); }
bool clean(std::string_view s,std::size_t maximum,bool empty=false) {
  return (empty||!s.empty())&&s.size()<=maximum&&std::none_of(s.begin(),s.end(),[](unsigned char c){return c<32||c==127;});
}
bool hash(std::string_view s) { return s.size()==64&&std::all_of(s.begin(),s.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}); }
bool decimal(std::string_view s) { return !s.empty()&&s.size()<=20&&(s.size()==1||s.front()!='0')&&std::all_of(s.begin(),s.end(),[](char c){return c>='0'&&c<='9';}); }
std::string lower(std::string s) { for(auto& c:s)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');return s; }
bool dns(std::string_view s) {
  if(!clean(s,253)||s.find('.')==s.npos)return false;
  std::size_t start=0;for(std::size_t n=0;n<=s.size();++n) {
    if(n==s.size()||s[n]=='.') {if(n==start||n-start>63||s[start]=='-'||s[n-1]=='-')return false;start=n+1;}
    else if(!((s[n]>='a'&&s[n]<='z')||(s[n]>='0'&&s[n]<='9')||s[n]=='-'))return false;
  }return true;
}
template<std::size_t N> bool keys(const json::object& o,const char* const (&names)[N]) {
  return o.size()==N&&std::all_of(std::begin(names),std::end(names),[&](auto key){return o.contains(key);});
}
void links(const json::value& value) {
  const auto& a=value.as<json::array>();if(a.size()>128)fail();
  constexpr const char* names[]{"guid","domain","dn","kind","enabled","enforced","order"};
  std::set<std::string> seen;
  for(const auto& item:a) {const auto& l=item.as<json::object>();if(!keys(l,names)||!valid_uuid(l.at("guid").as<std::string>())||
      !dns(l.at("domain").as<std::string>())||!clean(l.at("dn").as<std::string>(),2048)||l.at("order").as<std::int64_t>()<1||
      l.at("order").as<std::int64_t>()>128)fail();
    const auto& kind=l.at("kind").as<std::string>();if(kind!="ou"&&kind!="domain"&&kind!="site")fail();
    (void)l.at("enabled").as<bool>();(void)l.at("enforced").as<bool>();
    if(!seen.insert(lower(l.at("dn").as<std::string>())+"/"+l.at("guid").as<std::string>()).second)fail();
  }
}
bool ou_dn(std::string_view value,std::string_view domain) {
  if(!clean(value,2048)||value.find('/')!=value.npos)return false;
  auto dn=lower(std::string(value));if(!dn.starts_with("ou="))return false;
  std::string suffix;std::size_t begin=0;
  for(std::size_t p=0;p<=domain.size();++p)if(p==domain.size()||domain[p]=='.'){
    suffix+=",dc=";suffix+=domain.substr(begin,p-begin);begin=p+1;
  }
  return dn.size()>suffix.size()&&dn.ends_with(suffix);
}
std::string root_dn(std::string_view domain) {
  std::string result;std::size_t begin{};
  for(std::size_t end=0;end<=domain.size();++end)if(end==domain.size()||domain[end]=='.'){
    if(!result.empty())result+=',';result+="dc=";result+=domain.substr(begin,end-begin);begin=end+1;
  }return result;
}
bool domain_scope(const job& j) {const auto* c=component(j);return c&&c->scope=="domain";}
std::string target_kind(const job& j) {return domain_scope(j)?"domain":"ou";}
std::string state_guid(const json::object& state) {
  const auto& g=state.at("gpo");return g.get_if<std::nullptr_t>()?std::string{}:g.as<json::object>().at("guid").as<std::string>();
}
std::string managed_marker(const job& j) {return "IPMS managed GPO; id="+j.text("managed_id");}
json::array unrelated(json::array list,std::string_view id) {
  list.erase(std::remove_if(list.begin(),list.end(),[&](const auto& v){return v.template as<json::object>().at("guid").template as<std::string>()==id;}),list.end());
  for(auto& v:list)v.as<json::object>().erase("order");return list;
}
void postconditions(const job& j,const json::object& before,const json::object& after) {
  if(!valid_snapshot(after)||!after.at("name_available").as<bool>())fail("gpo_verification_failed");
  const auto& g=after.at("gpo").as<json::object>();const auto& op=j.text("operation");
  const auto id=g.at("guid").as<std::string>();
  const auto& original=before.at("gpo");
  if(!original.get_if<std::nullptr_t>()) {
    const auto& prior=original.as<json::object>();
    if(g.at("security_digest")!=prior.at("security_digest"))fail("gpo_verification_failed");
    if(op!="activate_managed_gpo")for(const auto* key:{"computer_ds","computer_sysvol","user_ds","user_sysvol"})if(g.at(key)!=prior.at(key))fail("gpo_verification_failed");
    if(op=="deactivate_managed_gpo"&&g.at("links")!=prior.at("links"))fail("gpo_verification_failed");
  }
  const auto& a=before.at("ous").as<json::array>();const auto& b=after.at("ous").as<json::array>();if(a.size()!=b.size())fail("gpo_verification_failed");
  for(std::size_t n=0;n<a.size();++n) {
    const auto& x=a[n].as<json::object>();const auto& y=b[n].as<json::object>();
    for(const auto* key:{"dn","guid","blocked"})if(x.at(key)!=y.at(key))fail("gpo_verification_failed");
    for(const auto* key:{"links","inherited_links"})if(unrelated(x.at(key).as<json::array>(),id)!=unrelated(y.at(key).as<json::array>(),id))fail("gpo_verification_failed");
    if(op=="import_managed_gpo"||op=="deactivate_managed_gpo")if(a[n]!=b[n])fail("gpo_verification_failed");
  }
  if(op=="import_managed_gpo"||op=="activate_managed_gpo")if(g.at("name").as<std::string>()!=j.text("pilot_display_name"))fail("gpo_verification_failed");
  if(op=="link_managed_gpo"||op=="activate_managed_gpo") {
    const auto& ls=g.at("links").as<json::array>();const auto& targets=j.fields.at("target_ous").as<json::array>();
    const auto& orders=j.fields.at("link_orders").as<json::array>();if(ls.size()!=targets.size())fail("gpo_verification_failed");
    for(std::size_t n=0;n<targets.size();++n) {
      const auto found=std::find_if(ls.begin(),ls.end(),[&](const auto& v){return lower(v.template as<json::object>().at("dn").template as<std::string>())==lower(targets[n].as<std::string>());});
      if(found==ls.end())fail("gpo_verification_failed");const auto& l=found->as<json::object>();
      if(l.at("kind").as<std::string>()!=target_kind(j)||l.at("domain").as<std::string>()!=j.text("domain_dns_name")||l.at("enforced").as<bool>()||
        l.at("enabled").as<bool>()!=(op=="activate_managed_gpo")||l.at("order")!=orders[n])fail("gpo_verification_failed");
    }
  }
  if(op=="activate_managed_gpo") {
    const auto* content=component(j);if(!content||g.at("computer_enabled").as<bool>()!=(content->scope=="machine"||content->scope=="domain")||
      g.at("user_enabled").as<bool>()!=(content->scope=="user"))fail("gpo_verification_failed");
  }
}
json::object terminal(journal& j,std::string_view status,std::string_view code,json::object state,
    const persist& save,std::string_view backup_id={},std::string_view backup_hash={}) {
  j.gpo_guid=state_guid(state);j.result=result(status,code,j.gpo_guid,managed_evidence(j.assignment,std::move(state),backup_id,backup_hash));
  j.state=phase::terminal;save(j);return j.result.as<json::object>();
}
}
void validate_forest_domains(const job& j,const std::vector<forest_domain>& domains) {
  if(domains.empty()||domains.size()>32)fail("gpo_preflight_required");
  std::set<std::string> names,ids;std::size_t primary{};bool root=false;
  for(const auto& d:domains) {
    if(!dns(d.dns_name)||!valid_uuid(d.guid)||!names.insert(d.dns_name).second||!ids.insert(d.guid).second)fail("gpo_preflight_required");
    if(d.primary) {++primary;if(d.dns_name!=j.text("domain_dns_name")||d.guid!=j.text("domain_guid"))fail("gpo_preflight_required");}
    root|=d.dns_name==j.text("forest_dns_name");
  }
  if(primary!=1||!root)fail("gpo_preflight_required");
}
std::optional<std::uint32_t> matching_gpo_link(std::string_view links,std::string_view policy_dn) {
  if(links.size()>65536)fail("gpo_preflight_required");std::optional<std::uint32_t> match;std::size_t offset{},count{};
  while(offset<links.size()) {
    if(links[offset]!='['||++count>128)fail("gpo_preflight_required");
    const auto end=links.find(']',offset+1);if(end==links.npos)fail("gpo_preflight_required");
    const auto segment=links.substr(offset+1,end-offset-1);const auto delimiter=segment.rfind(';');
    if(delimiter==segment.npos||delimiter+2!=segment.size()||segment[delimiter+1]<'0'||segment[delimiter+1]>'3')fail("gpo_preflight_required");
    const auto path=lower(std::string(segment.substr(0,delimiter)));
    if(!path.starts_with("ldap://")||path.size()<=7)fail("gpo_preflight_required");
    if(path.substr(7)==lower(std::string(policy_dn))) {
      if(match)fail("gpo_preflight_required");match=static_cast<std::uint32_t>(segment[delimiter+1]-'0');
    }
    offset=end+1;
  }
  return match;
}
void verify_forest_link_census(const json::array& observed,const std::map<std::string,std::uint32_t>& complete) {
  if(observed.size()!=complete.size()||observed.size()>128)fail("gpo_preflight_required");std::set<std::string> seen;
  for(const auto& v:observed) {
    const auto& l=v.as<json::object>();const auto location=lower(l.at("dn").as<std::string>());const auto found=complete.find(location);
    if(found==complete.end()||!seen.insert(location).second||l.at("enabled").as<bool>()!=((found->second&1)==0)||
      l.at("enforced").as<bool>()!=((found->second&2)!=0))fail("gpo_preflight_required");
  }
}
bool managed_operation(std::string_view op) {
  return op=="import_managed_gpo"||op=="link_managed_gpo"||op=="activate_managed_gpo"||op=="deactivate_managed_gpo";
}
bool inspection(const job& j) {return j.number("schema")==3&&j.text("operation")=="inspect_managed_gpo";}
bool valid_snapshot(const json::value& value) {try {
  if(json::serialize(value).size()>16384)return false;
  const auto& s=value.as<json::object>();constexpr const char* sk[]{"schema","gpo","ous","name_available"};
  if(!keys(s,sk)||s.at("schema").as<std::int64_t>()!=1)return false;(void)s.at("name_available").as<bool>();
  const auto& ous=s.at("ous").as<json::array>();if(ous.size()>32)return false;
  std::set<std::string> ids,dns_seen;
  constexpr const char* ok[]{"dn","guid","usn","blocked","links","inherited_links"};
  for(const auto& item:ous) {const auto& o=item.as<json::object>();if(!keys(o,ok)||!clean(o.at("dn").as<std::string>(),2048)||
      !valid_uuid(o.at("guid").as<std::string>())||!decimal(o.at("usn").as<std::string>())||
      !ids.insert(o.at("guid").as<std::string>()).second||!dns_seen.insert(lower(o.at("dn").as<std::string>())).second)return false;
    (void)o.at("blocked").as<bool>();links(o.at("links"));links(o.at("inherited_links"));
  }
  if(!s.at("gpo").get_if<std::nullptr_t>()) {
    const auto& g=s.at("gpo").as<json::object>();constexpr const char* gk[]{"guid","name","description","computer_enabled","user_enabled",
      "computer_ds","computer_sysvol","user_ds","user_sysvol","security_digest","wmi_filter","links"};
    if(!keys(g,gk)||!valid_uuid(g.at("guid").as<std::string>())||protected_gpo(g.at("guid").as<std::string>())||
        !clean(g.at("name").as<std::string>(),240)||!clean(g.at("description").as<std::string>(),2048,true)||
        !clean(g.at("wmi_filter").as<std::string>(),2048,true)||!hash(g.at("security_digest").as<std::string>()))return false;
    (void)g.at("computer_enabled").as<bool>();(void)g.at("user_enabled").as<bool>();
    for(const auto* key:{"computer_ds","computer_sysvol","user_ds","user_sysvol"})if(g.at(key).as<std::int64_t>()<0)return false;
    links(g.at("links"));
  }
  return true;
}catch(...){return false;}}
void validate_managed_job(const job& j) {
  constexpr const char* extra[]{"managed_id","managed_revision","gpo_guid","owner_marker","target_ous","link_orders",
    "preflight_id","expected_state","intended_operation","safety_review"};
  for(const auto* k:extra)if(!j.fields.contains(k))fail();
  if(!valid_uuid(j.text("managed_id"))||j.number("managed_revision")<1||!managed_operation(j.text("intended_operation")))fail();
  const bool read=inspection(j);
  const auto* content=component(j);
  const bool root=domain_scope(j);
  if(root&&j.number("target_tier")!=0)fail("gpo_target_invalid");
  if(content&&content->scope!="machine"&&content->scope!="user"&&content->scope!="domain")fail("gpo_unsupported_component");
  if(j.text("approval_mode")!=(read?"inspection":"portal")||(!read&&j.text("operation")!=j.text("intended_operation")))fail();
  const auto& id=j.text("gpo_guid");if(!id.empty()&&(!valid_uuid(id)||protected_gpo(id)))fail();
  if(id.empty()&&j.text("intended_operation")!="import_managed_gpo")fail();
  const auto& marker=j.text("owner_marker");
  if(id.empty()) {if(!marker.empty())fail();}
  else if(marker!=managed_marker(j)) {
    constexpr std::string_view prefix="IPMS disabled, unlinked pilot; job=";
    if(j.text("intended_operation")!="import_managed_gpo"||!marker.starts_with(prefix)||
        marker.size()!=prefix.size()+36+9+64||!valid_uuid(std::string_view(marker).substr(prefix.size(),36))||
        std::string_view(marker).substr(prefix.size()+36,9)!="; digest="||!hash(std::string_view(marker).substr(prefix.size()+45)))fail();
  }
  const auto& ous=j.fields.at("target_ous").as<json::array>();const auto& orders=j.fields.at("link_orders").as<json::array>();
  if(ous.size()>32||orders.size()!=ous.size()||(ous.empty()&&j.text("intended_operation")!="import_managed_gpo"))fail();
  std::set<std::string> seen;
  if(root&&((j.text("intended_operation")=="import_managed_gpo"&&!ous.empty())||
    (j.text("intended_operation")!="import_managed_gpo"&&ous.size()!=1)))fail("gpo_target_invalid");
  for(std::size_t n=0;n<ous.size();++n)if((root?lower(ous[n].as<std::string>())!=root_dn(j.text("domain_dns_name")):!ou_dn(ous[n].as<std::string>(),j.text("domain_dns_name")))||
      !seen.insert(lower(ous[n].as<std::string>())).second||orders[n].as<std::int64_t>()<1||orders[n].as<std::int64_t>()>128)fail();
  const auto& safety=j.fields.at("safety_review").as<json::object>();constexpr const char* safety_keys[]{"management_access","recovery_access"};
  if(!keys(safety,safety_keys))fail();const bool activation=!read&&j.text("operation")=="activate_managed_gpo";
  if(safety.at("management_access").as<bool>()!=activation||safety.at("recovery_access").as<bool>()!=activation)fail();
  if(read) {if(!j.text("preflight_id").empty()||!j.fields.at("expected_state").get_if<std::nullptr_t>())fail();}
  else {
    if(!valid_uuid(j.text("preflight_id"))||!valid_snapshot(j.fields.at("expected_state")))fail();
    const auto& state=j.fields.at("expected_state").as<json::object>();
    if(state_guid(state)!=id||state.at("ous").as<json::array>().size()!=ous.size())fail();
    for(std::size_t n=0;n<ous.size();++n)if(lower(state.at("ous").as<json::array>()[n].as<json::object>().at("dn").as<std::string>())!=lower(ous[n].as<std::string>()))fail();
  }
}
void validate_managed_state(const job& j,const json::object& state) {
  if(!valid_snapshot(state)||state_guid(state)!=j.text("gpo_guid"))fail("gpo_state_changed");
  if(!state.at("name_available").as<bool>())fail("gpo_name_collision");
  const auto& ous=state.at("ous").as<json::array>();const auto& targets=j.fields.at("target_ous").as<json::array>();
  if(ous.size()!=targets.size())fail("gpo_target_invalid");
  if(domain_scope(j))for(const auto& v:ous) {const auto& target=v.as<json::object>();
    if(target.at("guid").as<std::string>()!=j.text("domain_guid")||!target.at("inherited_links").as<json::array>().empty())fail("gpo_target_invalid");
  }
  for(std::size_t n=0;n<ous.size();++n)if(lower(ous[n].as<json::object>().at("dn").as<std::string>())!=lower(targets[n].as<std::string>()))fail("gpo_target_invalid");
  const auto& intended=j.text("intended_operation");
  if(intended=="link_managed_gpo")for(std::size_t n=0;n<ous.size();++n) {
    const auto& direct=ous[n].as<json::object>().at("links").as<json::array>();
    const auto own=std::count_if(direct.begin(),direct.end(),[&](const auto& v){return v.template as<json::object>().at("guid").template as<std::string>()==j.text("gpo_guid");});
    const auto count=direct.size()-static_cast<std::size_t>(own)+1;
    const auto order=j.fields.at("link_orders").as<json::array>()[n].as<std::int64_t>();
    if(own>1||count>128||order<1||static_cast<std::size_t>(order)>count)fail("gpo_link_conflict");
  }
  const bool changes_state=intended!="import_managed_gpo"||j.text("gpo_guid").empty()||j.text("owner_marker")!=managed_marker(j);
  if(changes_state) {
    // Reserve result capacity before claiming an irreversible write. New links
    // appear both in the GPO and OU views; nested targets can also inherit them.
    // Existing-content preparation needs no reserve because it changes no AD.
    std::size_t reserve=1024+targets.size()*64;
    if(intended=="link_managed_gpo")for(const auto& target:targets) {
      const json::object link{{"guid",j.text("gpo_guid")},{"domain",j.text("domain_dns_name")},{"dn",target.as<std::string>()},
        {"kind",target_kind(j)},{"enabled",false},{"enforced",false},{"order",128}};
      reserve+=json::serialize(link).size()*(2+targets.size());
    }
    if(json::serialize(state).size()+reserve>16384)fail("gpo_target_invalid");
  }
  if(state.at("gpo").get_if<std::nullptr_t>())return;
  const auto& g=state.at("gpo").as<json::object>();
  if(g.at("description").as<std::string>()!=j.text("owner_marker"))fail("gpo_unmanaged_target");
  if(!g.at("wmi_filter").as<std::string>().empty()||g.at("computer_ds")!=g.at("computer_sysvol")||g.at("user_ds")!=g.at("user_sysvol"))fail("gpo_state_changed");
  const auto& op=j.text("intended_operation");const bool disabled=!g.at("computer_enabled").as<bool>()&&!g.at("user_enabled").as<bool>();
  if((op=="link_managed_gpo"||j.text("owner_marker")!=managed_marker(j))&&!disabled)fail("gpo_requires_disabled");
  const auto& existing=g.at("links").as<json::array>();
  if(j.text("owner_marker")!=managed_marker(j)&&!existing.empty())fail("gpo_unmanaged_target");
  if(op=="link_managed_gpo"||op=="activate_managed_gpo"||op=="deactivate_managed_gpo") {
    std::set<std::string> seen;
    for(const auto& v:existing) {const auto& l=v.as<json::object>();const auto dn=lower(l.at("dn").as<std::string>());
      if(l.at("kind").as<std::string>()!=target_kind(j)||l.at("domain").as<std::string>()!=j.text("domain_dns_name")||l.at("enforced").as<bool>()||
          std::none_of(targets.begin(),targets.end(),[&](const auto& t){return lower(t.template as<std::string>())==dn;}))fail("gpo_link_conflict");
      seen.insert(dn);
    }
    if(op=="activate_managed_gpo"&&seen.size()!=targets.size())fail("gpo_link_conflict");
    if(!inspection(j)&&op=="activate_managed_gpo")for(std::size_t n=0;n<targets.size();++n) {
      const auto found=std::find_if(existing.begin(),existing.end(),[&](const auto& v){return lower(v.template as<json::object>().at("dn").template as<std::string>())==lower(targets[n].as<std::string>());});
      if(found==existing.end()||found->as<json::object>().at("order")!=j.fields.at("link_orders").as<json::array>()[n])fail("gpo_link_conflict");
    }
  }
}
json::object managed_evidence(const job& j,json::object state,std::string_view backup_id,std::string_view backup_hash) {
  return {{"schema",3},{"operation",j.text("operation")},{"managed_id",j.text("managed_id")},{"state",std::move(state)},
    {"prepared_artifact_sha256",j.text("operation")=="import_managed_gpo"||j.text("operation")=="activate_managed_gpo"?j.text("artifact_sha256"):""},
    {"backup_id",backup_id},{"backup_manifest_sha256",backup_hash}};
}
bool valid_managed_result(const json::object& r) {try {
  const auto& e=r.at("evidence").as<json::object>();constexpr const char* names[]{"schema","operation","managed_id","state","prepared_artifact_sha256","backup_id","backup_manifest_sha256"};
  if(!keys(e,names)||e.at("schema").as<std::int64_t>()!=3||!valid_uuid(e.at("managed_id").as<std::string>())||!valid_snapshot(e.at("state")))return false;
  const auto& op=e.at("operation").as<std::string>();const auto& s=r.at("status").as<std::string>();const auto& c=r.at("result_code").as<std::string>();
  if(!((op=="inspect_managed_gpo"&&s=="inspected"&&c=="gpo_inspected")||(op=="import_managed_gpo"&&s=="staged"&&c=="gpo_prepared")||
    (op=="link_managed_gpo"&&s=="linked"&&c=="gpo_linked")||(op=="activate_managed_gpo"&&s=="activated"&&c=="gpo_activated")||
    (op=="deactivate_managed_gpo"&&s=="deactivated"&&c=="gpo_deactivated")))return false;
  const auto id=state_guid(e.at("state").as<json::object>());const auto* result_id=r.at("gpo_guid").get_if<std::string>();
  if(id.empty()?(!r.at("gpo_guid").get_if<std::nullptr_t>()||s!="inspected"):(!result_id||*result_id!=id))return false;
  const auto& artifact=e.at("prepared_artifact_sha256").as<std::string>();
  if(op=="import_managed_gpo"||op=="activate_managed_gpo") {if(!hash(artifact))return false;} else if(!artifact.empty())return false;
  const auto& bid=e.at("backup_id").as<std::string>();const auto& bh=e.at("backup_manifest_sha256").as<std::string>();
  if(bid.empty()?(!bh.empty()||op=="activate_managed_gpo"):(!valid_uuid(bid)||!hash(bh)||op!="activate_managed_gpo"))return false;
  return true;
}catch(...){return false;}}
json::object inspect_managed(journal& j,managed_provider& provider,const persist& save,const std::function<bool()>& authority) {
  if(!inspection(j.assignment)||j.state!=phase::prepared||!save||!authority||!j.portal_approval.get_if<std::nullptr_t>()||j.grant_deadline_tick)fail("gpo_journal_invalid");
  try {
    if(!authority())fail("gpo_authority_expired");auto state=provider.inspect();validate_managed_state(j.assignment,state);
    if(!authority())fail("gpo_authority_expired");return terminal(j,"inspected","gpo_inspected",std::move(state),save);
  }catch(const std::exception& e) {
    auto code=std::string(e.what());json::object r;
    try {r=result("failed",code);}catch(...){r=result("failed","gpo_provider_failed");}
    j.state=phase::terminal;j.result=r;save(j);return r;
  }
}
json::object execute_managed(journal& j,managed_provider& provider,const persist& save,const std::function<bool()>& authority,const std::function<void()>& consume) {
  if(j.assignment.number("schema")!=3||inspection(j.assignment)||!save||!authority||!consume)fail("gpo_journal_invalid");
  if(j.state==phase::terminal||j.state==phase::reconciliation)return j.result.as<json::object>();
  if(j.state!=phase::granted)fail("gpo_journal_invalid");
  bool write_intent=false;
  try {
    (void)portal_approval_receipt(j);if(!authority())fail("gpo_authority_expired");
    auto state=provider.inspect();validate_managed_state(j.assignment,state);
    if(json::value(state)!=j.assignment.fields.at("expected_state"))fail("gpo_state_changed");
    const auto& op=j.assignment.text("operation");const auto& target=j.assignment.text("gpo_guid");
    const bool adoption=!target.empty()&&j.assignment.text("owner_marker")!=managed_marker(j.assignment);
    if(op=="import_managed_gpo"||op=="activate_managed_gpo")provider.prepare();
    std::pair<std::string,std::string> backup;
    if(op=="activate_managed_gpo") {
      backup=provider.backup(target);if(!valid_uuid(backup.first)||!hash(backup.second))fail("gpo_backup_failed");
    }
    if(json::value(provider.inspect())!=j.assignment.fields.at("expected_state"))fail("gpo_state_changed");
    if(!authority())fail("gpo_authority_expired");consume();
    if(op=="import_managed_gpo"&&!target.empty()&&!adoption)return terminal(j,"staged","gpo_prepared",std::move(state),save);
    j.state=phase::creating;save(j);write_intent=true;
    if(!authority())fail("gpo_authority_expired");
    j.gpo_guid=target.empty()?provider.create():target;
    if(!valid_uuid(j.gpo_guid)||protected_gpo(j.gpo_guid))fail("gpo_verification_failed");
    j.state=phase::created;save(j);j.state=phase::importing;save(j);
    if(op=="import_managed_gpo") {if(adoption)provider.adopt(j.gpo_guid);else provider.initialize(j.gpo_guid);}
    else if(op=="link_managed_gpo")provider.link(j.gpo_guid);
    else if(op=="activate_managed_gpo")provider.activate(j.gpo_guid);
    else provider.deactivate(j.gpo_guid);
    auto after=provider.inspect();
    if(state_guid(after)!=j.gpo_guid)fail("gpo_verification_failed");
    const auto& g=after.at("gpo").as<json::object>();
    if(g.at("description").as<std::string>()!=managed_marker(j.assignment)||!g.at("wmi_filter").as<std::string>().empty()||
      g.at("computer_ds")!=g.at("computer_sysvol")||g.at("user_ds")!=g.at("user_sysvol"))fail("gpo_verification_failed");
    if(op!="activate_managed_gpo"&&(g.at("computer_enabled").as<bool>()||g.at("user_enabled").as<bool>()))fail("gpo_verification_failed");
    if(op=="import_managed_gpo"&&!g.at("links").as<json::array>().empty())fail("gpo_verification_failed");
    postconditions(j.assignment,state,after);
    const auto status=op=="import_managed_gpo"?"staged":op=="link_managed_gpo"?"linked":op=="activate_managed_gpo"?"activated":"deactivated";
    const auto code=op=="import_managed_gpo"?"gpo_prepared":op=="link_managed_gpo"?"gpo_linked":op=="activate_managed_gpo"?"gpo_activated":"gpo_deactivated";
    return terminal(j,status,code,std::move(after),save,backup.first,backup.second);
  }catch(const std::exception& e) {
    const auto status=write_intent?"requires_reconciliation":"failed";json::object r;
    try {r=result(status,e.what(),write_intent?j.gpo_guid:std::string{});}catch(...){r=result(status,"gpo_provider_failed",write_intent?j.gpo_guid:std::string{});}
    j.state=write_intent?phase::reconciliation:phase::terminal;j.result=r;save(j);return r;
  }
}
}  // namespace ipms::agent::gpo
