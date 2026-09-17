// File Name: gpo_reconciliation.cpp
// Version: v0.1.1 | Created: 2026-09-15 | Last Modified: 2026-09-17
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Bounded reconciliation documents never authorize AD mutations.
#include "ipms/agent/gpo_reconciliation.hpp"
#include "ipms/agent/gpo_override.hpp"
#include <algorithm>
#include <set>

namespace ipms::agent::gpo {
namespace {
[[noreturn]] void invalid() { throw operation_error("gpo_journal_invalid"); }
bool hash(std::string_view s) {return s.size()==64&&std::all_of(s.begin(),s.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});}
template<std::size_t N> bool keys(const json::object& o,const char* const (&names)[N]) {
  return o.size()==N&&std::all_of(std::begin(names),std::end(names),[&](auto n){return o.contains(n);});
}
std::string lower(std::string s) {for(auto& c:s)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');return s;}
std::chrono::system_clock::time_point expiry(std::string_view s) {
  if(s.size()!=20||s[4]!='-'||s[7]!='-'||s[10]!='T'||s[13]!=':'||s[16]!=':'||s[19]!='Z')invalid();
  const auto number=[&](std::size_t begin,std::size_t count){int out{};for(std::size_t n=begin;n<begin+count;++n){if(s[n]<'0'||s[n]>'9')invalid();out=out*10+s[n]-'0';}return out;};
  const std::chrono::year_month_day day{std::chrono::year(number(0,4)),std::chrono::month(number(5,2)),std::chrono::day(number(8,2))};
  const auto h=number(11,2),m=number(14,2),sec=number(17,2);if(!day.ok()||h>23||m>59||sec>59)invalid();
  return std::chrono::sys_days(day)+std::chrono::hours(h)+std::chrono::minutes(m)+std::chrono::seconds(sec);
}
}
bool reconciliation_issue(std::string_view code) {
  constexpr std::string_view prefix="gpo_reconciliation_hresult_";
  if(code.starts_with(prefix)) {
    const auto hr=code.substr(prefix.size());
    return hr.size()==8&&((hr.front()>='8'&&hr.front()<='9')||(hr.front()>='a'&&hr.front()<='f'))&&
      std::all_of(hr.begin(),hr.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});
  }
  for(const auto* c:{"gpo_reconciliation_quiescence_unavailable","gpo_reconciliation_guid_unknown",
      "gpo_reconciliation_domain_open_failed","gpo_reconciliation_gpo_open_failed","gpo_reconciliation_metadata_failed",
      "gpo_reconciliation_worker_failed","gpo_reconciliation_worker_timeout","gpo_reconciliation_result_invalid","gpo_permission_denied",
      "gpo_reconciliation_state_unavailable","gpo_reconciliation_acl_inconsistent","gpo_preflight_required",
      "gpo_identity_mismatch","gpo_state_changed","gpo_target_invalid"})if(code==c)return true;
  return false;
}
json::object unavailable_observation(std::string_view id,std::string_view issue,bool quiet) {
  if(!reconciliation_issue(issue)||(!id.empty()&&(!valid_uuid(id)||protected_gpo(id))))invalid();
  return {{"schema",1},{"state",nullptr},{"forest_links",json::array{}},{"forest_complete",false},
    {"acl_consistent",nullptr},{"gpo_presence","unknown"},{"issues",json::array{json::value(issue)}},
    {"gpo_guid",id},{"quiescent",quiet}};
}
bool valid_reconciliation_observation(const json::value& v) {try {
  if(json::serialize(v).size()>32768)return false;
  const auto& o=v.as<json::object>();constexpr const char* names[]{"schema","state","forest_links","forest_complete","acl_consistent","gpo_presence","issues","gpo_guid","quiescent"};
  if(!keys(o,names)||o.at("schema").as<std::int64_t>()!=1)return false;
  const auto& id=o.at("gpo_guid").as<std::string>();if(!id.empty()&&(!valid_uuid(id)||protected_gpo(id)))return false;
  const auto& presence=o.at("gpo_presence").as<std::string>();if(presence!="present"&&presence!="absent"&&presence!="unknown")return false;
  (void)o.at("quiescent").as<bool>();const bool complete=o.at("forest_complete").as<bool>();
  if(!o.at("acl_consistent").get_if<std::nullptr_t>())(void)o.at("acl_consistent").as<bool>();
  const auto& issues=o.at("issues").as<json::array>();if(issues.size()>8)return false;std::set<std::string> seen;
  for(const auto& issue:issues)if(!reconciliation_issue(issue.as<std::string>())||!seen.insert(issue.as<std::string>()).second)return false;
  const auto& links=o.at("forest_links").as<json::array>();
  if(!valid_gpo_links(links))return false;
  for(const auto& link:links)if(link.as<json::object>().at("guid").as<std::string>()!=id)return false;
  if(!o.at("state").get_if<std::nullptr_t>()) {
    if(!valid_snapshot(o.at("state")))return false;const auto& g=o.at("state").as<json::object>().at("gpo");
    if(g.get_if<std::nullptr_t>()) {if(presence!="absent")return false;}
    else if(presence!="present"||g.as<json::object>().at("guid").as<std::string>()!=id||
        (complete&&g.as<json::object>().at("links")!=o.at("forest_links")))return false;
  }
  if(complete&&(id.empty()||presence=="unknown"))return false;
  return true;
}catch(...){return false;}}
bool acceptable_reconciliation_observation(const journal& j,const json::object& o) {try {
  if(j.state!=phase::reconciliation||(j.assignment.number("schema")<3||j.assignment.number("schema")>4)||j.gpo_guid.empty()||!valid_reconciliation_observation(o)||
      o.at("gpo_guid").as<std::string>()!=j.gpo_guid||!o.at("quiescent").as<bool>()||!o.at("forest_complete").as<bool>()||
      !o.at("acl_consistent").get_if<bool>()||!o.at("acl_consistent").as<bool>()||!o.at("issues").as<json::array>().empty()||
      o.at("gpo_presence").as<std::string>()!="present")return false;
  const auto& state=o.at("state").as<json::object>();const auto& g=state.at("gpo").as<json::object>();
  if(g.at("computer_enabled").as<bool>()||g.at("user_enabled").as<bool>()||
      g.at("description").as<std::string>()!=(override_job(j.assignment)?"IPMS managed override; id="+j.assignment.text("managed_id")+"; definition="+j.assignment.text("override_id"):"IPMS managed GPO; id="+j.assignment.text("managed_id"))||
      !g.at("wmi_filter").as<std::string>().empty()||g.at("computer_ds")!=g.at("computer_sysvol")||g.at("user_ds")!=g.at("user_sysvol"))return false;
  const auto& targets=j.assignment.fields.at("target_ous").as<json::array>();const auto& ous=state.at("ous").as<json::array>();if(targets.size()!=ous.size())return false;
  for(std::size_t i=0;i<targets.size();++i)if(lower(targets[i].as<std::string>())!=lower(ous[i].as<json::object>().at("dn").as<std::string>()))return false;
  const auto* c=component(j.assignment);if(!c)return false;const bool root=domain_target(j.assignment);
  if(root&&(j.assignment.number("target_tier")!=0||
      (!ous.empty()&&ous.front().as<json::object>().at("guid").as<std::string>()!=j.assignment.text("domain_guid"))))return false;
  for(const auto& item:o.at("forest_links").as<json::array>()) {
    const auto& l=item.as<json::object>();
    if(l.at("domain").as<std::string>()!=j.assignment.text("domain_dns_name")||l.at("enforced").as<bool>()||
        l.at("kind").as<std::string>()!=(root?"domain":"ou"))return false;
    if(std::none_of(targets.begin(),targets.end(),[&](const auto& dn){return lower(dn.template as<std::string>())==lower(l.at("dn").as<std::string>());}))return false;
  }
  json::array direct;for(const auto& target:ous)for(const auto& link:target.as<json::object>().at("links").as<json::array>())
    if(link.as<json::object>().at("guid").as<std::string>()==j.gpo_guid)direct.push_back(link);
  auto forest=o.at("forest_links").as<json::array>();const auto sort=[](auto& links){std::sort(links.begin(),links.end(),[](const auto& a,const auto& b){return json::serialize(a)<json::serialize(b);});};
  sort(direct);sort(forest);if(direct!=forest)return false;
  return true;
}catch(...){return false;}}
json::object parse_reconciliation(const json::value& value,const journal& j,std::string_view digest,bool current) {
  try {
    const auto& o=value.as<json::object>();constexpr const char* names[]{"schema","id","job_id","input_digest","journal_sha256","device_uri","expires_at","mode","observation_digest"};
    if(!keys(o,names)||o.at("schema").as<std::int64_t>()!=1||!valid_uuid(o.at("id").as<std::string>())||!hash(digest)||
        j.state!=phase::reconciliation||(j.assignment.number("schema")<3||j.assignment.number("schema")>4)||o.at("job_id").as<std::string>()!=j.assignment.text("job_id")||
        o.at("input_digest").as<std::string>()!=j.assignment.text("input_digest")||o.at("journal_sha256").as<std::string>()!=digest||
        o.at("device_uri").as<std::string>()!=j.device_uri)invalid();
    const auto& mode=o.at("mode").as<std::string>();const auto& observed=o.at("observation_digest").as<std::string>();
    if(mode=="observe"? !observed.empty() : ((mode!="accept"&&mode!="released")||!hash(observed)))invalid();
    // Expiry uses the same strict UTC grammar as executable assignments but
    // cannot extend the old execution grant or make the original job current.
    const auto deadline=expiry(o.at("expires_at").as<std::string>());const auto now=std::chrono::system_clock::now();
    if(current&&mode!="released"&&(deadline<=now||deadline>now+std::chrono::minutes(15)))invalid();
    return o;
  }catch(...){invalid();}
}
json::object reconciliation_sidecar(const json::object& c,const json::object& o) {
  if(!valid_reconciliation_observation(o)||c.at("observation_digest").as<std::string>()!=sha256(json::serialize(o)))invalid();
  return {{"schema",1},{"reconciliation",c},{"observation",o}};
}
bool valid_reconciliation_sidecar(const json::value& v,const journal& j,std::string_view digest,std::string_view mode) {try {
  const auto& s=v.as<json::object>();constexpr const char* names[]{"schema","reconciliation","observation"};
  if(!keys(s,names)||s.at("schema").as<std::int64_t>()!=1)return false;
  const auto c=parse_reconciliation(s.at("reconciliation"),j,digest,false);
  return c.at("mode").as<std::string>()==mode&&acceptable_reconciliation_observation(j,s.at("observation").as<json::object>())&&
    c.at("observation_digest").as<std::string>()==sha256(json::serialize(s.at("observation")));
}catch(...){return false;}}
json::object reconciliation_release(const json::object& released,const json::value& pending,const journal& j,std::string_view digest) {
  if(!valid_reconciliation_sidecar(pending,j,digest,"accept"))invalid();
  const auto c=parse_reconciliation(released,j,digest,false);auto previous=pending.as<json::object>().at("reconciliation").as<json::object>();previous["mode"]="released";
  if(c!=previous)invalid();return reconciliation_sidecar(c,pending.as<json::object>().at("observation").as<json::object>());
}
} // namespace ipms::agent::gpo
