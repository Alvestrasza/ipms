// File Name: gpo_managed.cpp
// Version: v0.2.0 | Created: 2026-09-15 | Last Modified: 2026-09-17
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Exact managed-GPO contracts, inspection isolation and durable write ordering.
#include "ipms/agent/gpo_managed.hpp"
#include "ipms/agent/gpo_override.hpp"
#include <algorithm>
#include <set>

namespace ipms::agent::gpo {
namespace {
[[noreturn]] void fail(const char* code="gpo_invalid_job") { throw operation_error(code); }
bool clean(std::string_view s,std::size_t maximum,bool empty=false) {
  return (empty||!s.empty())&&s.size()<=maximum&&std::none_of(s.begin(),s.end(),[](unsigned char c){return c<32||c==127;});
}
bool hash(std::string_view s) { return s.size()==64&&std::all_of(s.begin(),s.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}); }
bool sid(std::string_view s) {
  if(!s.starts_with("S-1-")||s.size()>184||s.back()=='-')return false;
  std::size_t begin=4;unsigned parts{};
  while(begin<s.size()) {
    const auto end=s.find('-',begin),length=(end==s.npos?s.size():end)-begin;
    if(!length||(length>1&&s[begin]=='0'))return false;
    std::uint64_t value{};const auto maximum=parts==0?281474976710655ULL:4294967295ULL;
    for(std::size_t n=begin;n<begin+length;++n){if(s[n]<'0'||s[n]>'9'||value>(maximum-static_cast<unsigned>(s[n]-'0'))/10)return false;value=value*10+static_cast<unsigned>(s[n]-'0');}
    if(++parts>16)return false;if(end==s.npos)break;begin=end+1;
  }
  return parts>=2;
}
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
std::string target_kind(const job& j) {return domain_target(j)?"domain":"ou";}
std::string state_guid(const json::object& state) {
  const auto& g=state.at("gpo");return g.get_if<std::nullptr_t>()?std::string{}:g.as<json::object>().at("guid").as<std::string>();
}
std::string managed_marker(const job& j) {return override_job(j)?"IPMS managed override; id="+j.text("managed_id")+"; definition="+j.text("override_id"):"IPMS managed GPO; id="+j.text("managed_id");}
bool import_operation(std::string_view op) {return op=="import_managed_gpo"||op=="import_and_link_managed_gpo";}
bool link_operation(std::string_view op) {return op=="link_managed_gpo"||op=="import_and_link_managed_gpo";}

json::array unrelated(json::array list,std::string_view id) {
  list.erase(std::remove_if(list.begin(),list.end(),[&](const auto& v){return v.template as<json::object>().at("guid").template as<std::string>()==id;}),list.end());
  for(auto& v:list)v.as<json::object>().erase("order");return list;
}
void postconditions(const job& j,const json::object& before,const json::object& after) {
  if(!valid_snapshot(after)||!after.at("name_available").as<bool>())fail("gpo_verification_failed");
  if(after.at("domain_admins_sid")!=before.at("domain_admins_sid"))fail("gpo_verification_failed");
  const auto& op=j.text("operation");const auto& original=before.at("gpo");
  if(op=="delete_managed_gpo") {
    if(original.get_if<std::nullptr_t>()||!after.at("gpo").get_if<std::nullptr_t>())fail("gpo_verification_failed");
    const auto id=original.as<json::object>().at("guid").as<std::string>();
    const auto& a=before.at("ous").as<json::array>();const auto& b=after.at("ous").as<json::array>();if(a.size()!=b.size())fail("gpo_verification_failed");
    for(std::size_t n=0;n<a.size();++n) {
      const auto& x=a[n].as<json::object>();const auto& y=b[n].as<json::object>();
      for(const auto* key:{"dn","guid","blocked","inherited_links"})if(x.at(key)!=y.at(key))fail("gpo_verification_failed");
      auto expected=x.at("links").as<json::array>();
      expected.erase(std::remove_if(expected.begin(),expected.end(),[&](const auto& v){return v.template as<json::object>().at("guid").template as<std::string>()==id;}),expected.end());
      const auto& actual=y.at("links").as<json::array>();
      for(std::size_t i=0;i<expected.size();++i)expected[i].as<json::object>()["order"]=static_cast<std::int64_t>(i+1);
      if(actual!=expected)fail("gpo_verification_failed");
    }
    return;
  }
  const auto& g=after.at("gpo").as<json::object>();const auto id=g.at("guid").as<std::string>();
  if(!original.get_if<std::nullptr_t>()) {
    const auto& prior=original.as<json::object>();
    if(g.at("security_digest")!=prior.at("security_digest"))fail("gpo_verification_failed");
    if(op!="activate_managed_gpo")for(const auto* key:{"computer_ds","computer_sysvol","user_ds","user_sysvol"})if(g.at(key)!=prior.at(key))fail("gpo_verification_failed");
    if(op=="deactivate_managed_gpo"&&g.at("links")!=prior.at("links"))fail("gpo_verification_failed");
  }
  const bool owner_write=op=="activate_managed_gpo"||original.get_if<std::nullptr_t>()||j.text("owner_marker")!=managed_marker(j);
  if(owner_write) {
    if(g.at("owner_sid")!=after.at("domain_admins_sid"))fail("gpo_verification_failed");
  } else if(g.at("owner_sid")!=original.as<json::object>().at("owner_sid"))fail("gpo_verification_failed");
  const auto& a=before.at("ous").as<json::array>();const auto& b=after.at("ous").as<json::array>();if(a.size()!=b.size())fail("gpo_verification_failed");
  for(std::size_t n=0;n<a.size();++n) {
    const auto& x=a[n].as<json::object>();const auto& y=b[n].as<json::object>();
    for(const auto* key:{"dn","guid","blocked"})if(x.at(key)!=y.at(key))fail("gpo_verification_failed");
    for(const auto* key:{"links","inherited_links"})if(unrelated(x.at(key).as<json::array>(),id)!=unrelated(y.at(key).as<json::array>(),id))fail("gpo_verification_failed");
    if(op=="import_managed_gpo"||op=="deactivate_managed_gpo")if(a[n]!=b[n])fail("gpo_verification_failed");
  }
  if(op=="import_managed_gpo"||op=="activate_managed_gpo"||
      (op=="import_and_link_managed_gpo"&&(original.get_if<std::nullptr_t>()||j.text("owner_marker")!=managed_marker(j))))
    if(g.at("name").as<std::string>()!=j.text("pilot_display_name"))fail("gpo_verification_failed");
  if(op=="import_and_link_managed_gpo"&&!original.get_if<std::nullptr_t>()&&j.text("owner_marker")==managed_marker(j))
    if(g.at("name")!=original.as<json::object>().at("name"))fail("gpo_verification_failed");
  if(link_operation(op)||op=="activate_managed_gpo") {
    const auto& ls=g.at("links").as<json::array>();const auto& targets=j.fields.at("target_ous").as<json::array>();
    const auto& orders=j.fields.at("link_orders").as<json::array>();if(ls.size()!=targets.size())fail("gpo_verification_failed");
    for(std::size_t n=0;n<targets.size();++n) {
      const auto found=std::find_if(ls.begin(),ls.end(),[&](const auto& v){return lower(v.template as<json::object>().at("dn").template as<std::string>())==lower(targets[n].as<std::string>());});
      if(found==ls.end())fail("gpo_verification_failed");const auto& l=found->as<json::object>();
      if(l.at("kind").as<std::string>()!=target_kind(j)||l.at("domain").as<std::string>()!=j.text("domain_dns_name")||l.at("enforced").as<bool>()||
        l.at("enabled").as<bool>()!=(op=="activate_managed_gpo")||l.at("order")!=orders[n])fail("gpo_verification_failed");
      const auto& direct=b[n].as<json::object>().at("links").as<json::array>();
      const auto own=std::find_if(direct.begin(),direct.end(),[&](const auto& v){return v.template as<json::object>().at("guid").template as<std::string>()==id;});
      if(own==direct.end()||own->as<json::object>()!=l)fail("gpo_verification_failed");
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
void merge_forest_link_locations(std::map<std::string,std::uint32_t>& complete,
    const std::map<std::string,std::uint32_t>& observed) {
  // Separate authenticated naming-context reads may repeat a location.
  // Equal evidence is idempotent; conflicting flags remain a hard failure.
  for(const auto& [dn,flags]:observed) {
    const auto [existing,inserted]=complete.emplace(dn,flags);
    if((!inserted&&existing->second!=flags)||complete.size()>128)fail("gpo_preflight_required");
  }
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
  return import_operation(op)||op=="link_managed_gpo"||op=="activate_managed_gpo"||op=="deactivate_managed_gpo"||op=="delete_managed_gpo";
}
bool inspection(const job& j) {return j.number("schema")>=3&&j.text("operation")=="inspect_managed_gpo";}
bool domain_target(const job& j) {
  const auto* content=component(j);if(content&&content->scope=="domain")return true;
  if(!j.fields.contains("target_ous")||!j.fields.contains("domain_dns_name"))return false;
  const auto& targets=j.fields.at("target_ous").as<json::array>();
  return targets.size()==1&&lower(targets.front().as<std::string>())==root_dn(j.text("domain_dns_name"));
}
std::pair<std::string,std::string> ace_object_types(std::int64_t flags,
    const std::function<std::string()>& object_type,const std::function<std::string()>& inherited_object_type) {
  // ADS_FLAG_OBJECT_TYPE_PRESENT=1, ADS_FLAG_INHERITED_OBJECT_TYPE_PRESENT=2.
  // Absent GUID fields are not physically present in ordinary ACEs. Querying
  // them unconditionally can fail instead of returning an empty GUID string.
  if(flags<0||(flags&~3LL)!=0||!object_type||!inherited_object_type)fail("gpo_state_changed");
  return {(flags&1)?object_type():std::string{},(flags&2)?inherited_object_type():std::string{}};
}
bool valid_gpo_links(const json::value& value) {try {links(value);return true;}catch(...){return false;}}
bool valid_snapshot(const json::value& value) {try {
  if(json::serialize(value).size()>16384)return false;
  const auto& s=value.as<json::object>();constexpr const char* sk[]{"schema","domain_admins_sid","gpo","ous","name_available"};
  if(!keys(s,sk)||s.at("schema").as<std::int64_t>()!=1||!sid(s.at("domain_admins_sid").as<std::string>()))return false;(void)s.at("name_available").as<bool>();
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
      "computer_ds","computer_sysvol","user_ds","user_sysvol","owner_sid","security_digest","wmi_filter","links"};
    if(!keys(g,gk)||!valid_uuid(g.at("guid").as<std::string>())||protected_gpo(g.at("guid").as<std::string>())||
        !clean(g.at("name").as<std::string>(),240)||!clean(g.at("description").as<std::string>(),2048,true)||
        !clean(g.at("wmi_filter").as<std::string>(),2048,true)||!sid(g.at("owner_sid").as<std::string>())||!hash(g.at("security_digest").as<std::string>()))return false;
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
  const bool root=domain_target(j);
  const bool domain_content=content&&content->scope=="domain";
  if(root&&j.number("target_tier")!=0)fail("gpo_target_invalid");
  if(content&&content->scope!="machine"&&content->scope!="user"&&content->scope!="domain")fail("gpo_unsupported_component");
  if(j.text("approval_mode")!=(read?"inspection":"portal")||(!read&&j.text("operation")!=j.text("intended_operation")))fail();
  const auto& id=j.text("gpo_guid");if(!id.empty()&&(!valid_uuid(id)||protected_gpo(id)))fail();
  if(id.empty()&&!import_operation(j.text("intended_operation")))fail();
  const auto& marker=j.text("owner_marker");
  if(id.empty()) {if(!marker.empty())fail();}
  else if(marker!=managed_marker(j)) {
    if(override_job(j))fail("gpo_unmanaged_target");
    constexpr std::string_view prefix="IPMS disabled, unlinked pilot; job=";
    if(!import_operation(j.text("intended_operation"))||!marker.starts_with(prefix)||
        marker.size()!=prefix.size()+36+9+64||!valid_uuid(std::string_view(marker).substr(prefix.size(),36))||
        std::string_view(marker).substr(prefix.size()+36,9)!="; digest="||!hash(std::string_view(marker).substr(prefix.size()+45)))fail();
  }
  const auto& ous=j.fields.at("target_ous").as<json::array>();const auto& orders=j.fields.at("link_orders").as<json::array>();
  if(ous.size()>32||orders.size()!=ous.size()||(ous.empty()&&j.text("intended_operation")!="import_managed_gpo"))fail();
  std::set<std::string> seen;
  if(root&&((j.text("intended_operation")=="import_managed_gpo"&&
      (domain_content?!ous.empty():ous.size()!=1))||
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
  const bool confirmed_missing=inspection(j)&&j.text("intended_operation")=="delete_managed_gpo"&&
    !j.text("gpo_guid").empty()&&state.at("gpo").get_if<std::nullptr_t>();
  if(!valid_snapshot(state)||(!confirmed_missing&&state_guid(state)!=j.text("gpo_guid")))fail("gpo_state_changed");
  if(!state.at("name_available").as<bool>())fail("gpo_name_collision");
  const auto& ous=state.at("ous").as<json::array>();const auto& targets=j.fields.at("target_ous").as<json::array>();
  if(ous.size()!=targets.size())fail("gpo_target_invalid");
  if(domain_target(j))for(const auto& v:ous) {const auto& target=v.as<json::object>();
    if(target.at("guid").as<std::string>()!=j.text("domain_guid")||!target.at("inherited_links").as<json::array>().empty())fail("gpo_target_invalid");
  }
  for(std::size_t n=0;n<ous.size();++n)if(lower(ous[n].as<json::object>().at("dn").as<std::string>())!=lower(targets[n].as<std::string>()))fail("gpo_target_invalid");
  const auto& intended=j.text("intended_operation");
  if(link_operation(intended))for(std::size_t n=0;n<ous.size();++n) {
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
    if(link_operation(intended))for(const auto& target:targets) {
      const json::object link{{"guid",j.text("gpo_guid").empty()?j.text("managed_id"):j.text("gpo_guid")},{"domain",j.text("domain_dns_name")},{"dn",target.as<std::string>()},
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
  if((link_operation(op)||j.text("owner_marker")!=managed_marker(j))&&!disabled)fail("gpo_requires_disabled");
  const auto& existing=g.at("links").as<json::array>();
  if(j.text("owner_marker")!=managed_marker(j)&&!existing.empty())fail("gpo_unmanaged_target");
  if(link_operation(op)||op=="activate_managed_gpo"||op=="deactivate_managed_gpo"||op=="delete_managed_gpo") {
    std::set<std::string> seen;
    for(const auto& v:existing) {const auto& l=v.as<json::object>();const auto dn=lower(l.at("dn").as<std::string>());
      if(l.at("kind").as<std::string>()!=target_kind(j)||l.at("domain").as<std::string>()!=j.text("domain_dns_name")||l.at("enforced").as<bool>()||
          std::none_of(targets.begin(),targets.end(),[&](const auto& t){return lower(t.template as<std::string>())==dn;}))fail("gpo_link_conflict");
      seen.insert(dn);
    }
    if(op=="activate_managed_gpo"&&seen.size()!=targets.size())fail("gpo_link_conflict");
    if(!inspection(j)&&!override_job(j)&&op=="activate_managed_gpo")for(std::size_t n=0;n<targets.size();++n) {
      const auto found=std::find_if(existing.begin(),existing.end(),[&](const auto& v){return lower(v.template as<json::object>().at("dn").template as<std::string>())==lower(targets[n].as<std::string>());});
      if(found==existing.end()||found->as<json::object>().at("order")!=j.fields.at("link_orders").as<json::array>()[n])fail("gpo_link_conflict");
    }
  }
}
json::object managed_evidence(const job& j,json::object state,std::string_view backup_id,std::string_view backup_hash) {
  json::object evidence{{"schema",j.number("schema")},{"operation",j.text("operation")},{"managed_id",j.text("managed_id")},{"state",std::move(state)},
    {"prepared_artifact_sha256",import_operation(j.text("operation"))||j.text("operation")=="activate_managed_gpo"?j.text("artifact_sha256"):""},
    {"backup_id",backup_id},{"backup_manifest_sha256",backup_hash}};
  if(override_job(j))evidence.emplace("override_sha256",j.text("override_sha256"));return evidence;
}
bool valid_managed_result(const json::object& r) {try {
  const auto& e=r.at("evidence").as<json::object>();constexpr const char* names[]{"schema","operation","managed_id","state","prepared_artifact_sha256","backup_id","backup_manifest_sha256"};
  const auto schema=e.at("schema").as<std::int64_t>();
  auto base=e; if(schema==4){if(!hash(e.at("override_sha256").as<std::string>()))return false;base.erase("override_sha256");}
  if(!keys(base,names)||(schema!=3&&schema!=4)||!valid_uuid(e.at("managed_id").as<std::string>())||!valid_snapshot(e.at("state")))return false;
  const auto& op=e.at("operation").as<std::string>();const auto& s=r.at("status").as<std::string>();const auto& c=r.at("result_code").as<std::string>();
  if(!((op=="inspect_managed_gpo"&&s=="inspected"&&c=="gpo_inspected")||(op=="import_managed_gpo"&&s=="staged"&&c=="gpo_prepared")||
    (link_operation(op)&&s=="linked"&&c=="gpo_linked")||(op=="activate_managed_gpo"&&s=="activated"&&c=="gpo_activated")||
    (op=="deactivate_managed_gpo"&&s=="deactivated"&&c=="gpo_deactivated")||
    (op=="delete_managed_gpo"&&s=="deleted"&&c=="gpo_deleted")))return false;
  const auto id=state_guid(e.at("state").as<json::object>());const auto* result_id=r.at("gpo_guid").get_if<std::string>();
  if(id.empty()?(!r.at("gpo_guid").get_if<std::nullptr_t>()||(s!="inspected"&&s!="deleted")):(!result_id||*result_id!=id))return false;
  const auto& artifact=e.at("prepared_artifact_sha256").as<std::string>();
  if(import_operation(op)||op=="activate_managed_gpo") {if(!hash(artifact))return false;} else if(!artifact.empty())return false;
  const auto& bid=e.at("backup_id").as<std::string>();const auto& bh=e.at("backup_manifest_sha256").as<std::string>();
  if(bid.empty()?(!bh.empty()||op=="activate_managed_gpo"||op=="delete_managed_gpo"):
      (!valid_uuid(bid)||!hash(bh)||(op!="activate_managed_gpo"&&op!="delete_managed_gpo")))return false;
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
  if((j.assignment.number("schema")<3||j.assignment.number("schema")>4)||inspection(j.assignment)||!save||!authority||!consume)fail("gpo_journal_invalid");
  if(j.state==phase::terminal||j.state==phase::reconciliation)return j.result.as<json::object>();
  if(j.state!=phase::granted)fail("gpo_journal_invalid");
  bool write_intent=false;
  try {
    (void)portal_approval_receipt(j);if(!authority())fail("gpo_authority_expired");
    auto state=provider.inspect();validate_managed_state(j.assignment,state);
    if(json::value(state)!=j.assignment.fields.at("expected_state"))fail("gpo_state_changed");
    const auto& op=j.assignment.text("operation");const auto& target=j.assignment.text("gpo_guid");
    const bool adoption=!target.empty()&&j.assignment.text("owner_marker")!=managed_marker(j.assignment);
    if(import_operation(op)||op=="activate_managed_gpo")provider.prepare();
    std::pair<std::string,std::string> backup;
    if(op=="activate_managed_gpo"||op=="delete_managed_gpo") {
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
    if(import_operation(op)) {
      if(adoption)provider.adopt(j.gpo_guid);
      else if(target.empty())provider.initialize(j.gpo_guid);
      if(op=="import_and_link_managed_gpo") {
        // One immutable approval covers both writes. Re-read the complete
        // forest and target snapshot between them; only this exact newly
        // created/adopted GPO may differ from the originally approved state.
        const auto prepared=provider.inspect();
        if(!valid_snapshot(prepared)||state_guid(prepared)!=j.gpo_guid||!prepared.at("name_available").as<bool>()||
          prepared.at("ous")!=state.at("ous"))fail("gpo_state_changed");
        const auto& policy=prepared.at("gpo").as<json::object>();
        if(policy.at("computer_enabled").as<bool>()||policy.at("user_enabled").as<bool>()||
          policy.at("description").as<std::string>()!=managed_marker(j.assignment)||!policy.at("wmi_filter").as<std::string>().empty()||
          policy.at("computer_ds")!=policy.at("computer_sysvol")||policy.at("user_ds")!=policy.at("user_sysvol"))fail("gpo_verification_failed");
        if(target.empty()) {
          if(policy.at("name").as<std::string>()!=j.assignment.text("pilot_display_name")||!policy.at("links").as<json::array>().empty())fail("gpo_state_changed");
        } else {
          auto expected=state.at("gpo").as<json::object>();
          if(adoption) {expected["name"]=j.assignment.text("pilot_display_name");expected["description"]=managed_marker(j.assignment);}
          if(policy!=expected)fail("gpo_state_changed");
        }
        // Preserve a durable whole-operation intent and the concrete GUID.
        // Expiry/drift/failure from here requires reconciliation, never replay.
        save(j);if(!authority())fail("gpo_authority_expired");provider.link(j.gpo_guid);
      }
    }
    else if(op=="link_managed_gpo")provider.link(j.gpo_guid);
    else if(op=="activate_managed_gpo")provider.activate(j.gpo_guid);
    else if(op=="deactivate_managed_gpo")provider.deactivate(j.gpo_guid);
    else provider.remove(j.gpo_guid);
    auto after=provider.inspect();
    if(op=="delete_managed_gpo") {
      if(!state_guid(after).empty())fail("gpo_verification_failed");postconditions(j.assignment,state,after);
      return terminal(j,"deleted","gpo_deleted",std::move(after),save,backup.first,backup.second);
    }
    if(state_guid(after)!=j.gpo_guid)fail("gpo_verification_failed");
    const auto& g=after.at("gpo").as<json::object>();
    if(g.at("description").as<std::string>()!=managed_marker(j.assignment)||!g.at("wmi_filter").as<std::string>().empty()||
      g.at("computer_ds")!=g.at("computer_sysvol")||g.at("user_ds")!=g.at("user_sysvol"))fail("gpo_verification_failed");
    if(op!="activate_managed_gpo"&&(g.at("computer_enabled").as<bool>()||g.at("user_enabled").as<bool>()))fail("gpo_verification_failed");
    if(op=="import_managed_gpo"&&!g.at("links").as<json::array>().empty())fail("gpo_verification_failed");
    postconditions(j.assignment,state,after);
    const auto status=op=="import_managed_gpo"?"staged":link_operation(op)?"linked":op=="activate_managed_gpo"?"activated":"deactivated";
    const auto code=op=="import_managed_gpo"?"gpo_prepared":link_operation(op)?"gpo_linked":op=="activate_managed_gpo"?"gpo_activated":"gpo_deactivated";
    return terminal(j,status,code,std::move(after),save,backup.first,backup.second);
  }catch(const std::exception& e) {
    const auto status=write_intent?"requires_reconciliation":"failed";json::object r;
    try {r=result(status,e.what(),write_intent?j.gpo_guid:std::string{});}catch(...){r=result(status,"gpo_provider_failed",write_intent?j.gpo_guid:std::string{});}
    j.state=write_intent?phase::reconciliation:phase::terminal;j.result=r;save(j);return r;
  }
}
}  // namespace ipms::agent::gpo
