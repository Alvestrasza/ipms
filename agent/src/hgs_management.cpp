// File Name: hgs_management.cpp
// Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-20
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Reject unsafe HGS assignments and reconcile interrupted operations without replay.
#include "ipms/agent/hgs_management.hpp"
#include "ipms/agent/gpo_management.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <set>

namespace ipms::agent::hgs {
namespace {
const std::string& text(const json::object& o, const char* k) { return o.at(k).as<std::string>(); }
bool flag(const json::object& o, const char* k) { return o.at(k).as<bool>(); }
void require(bool condition) { if (!condition) throw error("hgs_contract_invalid"); }
void keys(const json::object& o, std::initializer_list<const char*> names) {
  require(o.size() == names.size()); for (const auto name : names) require(o.contains(name));
}
bool safe_text(std::string_view s, std::size_t maximum, bool empty = false) {
  return (empty || !s.empty()) && s.size() <= maximum && std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= 32 && c < 127; });
}
bool label(std::string_view s) {
  return !s.empty() && s.size() <= 63 && s.front() != '-' && s.back() != '-' &&
    std::all_of(s.begin(), s.end(), [](unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
}
bool dns(std::string_view s) {
  if (s.size() > 253 || s.find('.') == s.npos) return false;
  while (true) { const auto dot = s.find('.'); if (!label(s.substr(0,dot))) return false; if (dot == s.npos) return true; s.remove_prefix(dot+1); }
}
bool hex(std::string_view s, std::size_t n, bool upper = false) {
  return s.size() == n && std::all_of(s.begin(),s.end(),[upper](char c) { return (c >= '0' && c <= '9') || (upper ? (c >= 'A' && c <= 'F') : (c >= 'a' && c <= 'f')); });
}
bool reference(std::string_view s, bool empty = false) {
  return (empty || !s.empty()) && s.size() <= 64 && std::all_of(s.begin(),s.end(),[](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'; });
}
bool source_path(std::string_view s) {
  if (!safe_text(s,240) || s.size() < 4 || !std::isalpha(static_cast<unsigned char>(s[0])) || s[1] != ':' || s[2] != '\\') return false;
  if (s.find("..") != s.npos || s.find_first_of("\"<>|?*$;`\r\n") != s.npos || s.find(':',2) != s.npos) return false;
  return true;
}
bool operation(std::string_view s) { return s == "inspect" || s == "install_role" || s == "create_forest" || s == "join_node" || s == "initialize" || s == "verify" || s == "reboot"; }
bool read_only(const job& j) { return j.text("operation") == "inspect" || j.text("operation") == "verify"; }
json::object finish(journal& j, const persist& save, std::string_view status, std::string_view code, json::object observed = {}) {
  j.state = phase::terminal; j.outcome = result(status,code,std::move(observed)); save(j); return j.outcome;
}
}
job parse_job(const json::value& input) {
  try {
    const auto& o = input.as<json::object>();
    keys(o,{"schema_version","job_id","deployment_id","tenant_id","enrollment_id","device_uri","plan_digest","operation","config","expires_at"});
    require(o.at("schema_version").as<std::int64_t>() == 1);
    for (const auto name : {"job_id","deployment_id","tenant_id","enrollment_id"}) require(gpo::valid_uuid(text(o,name)));
    require(text(o,"device_uri").starts_with("urn:ipms:agent:") && gpo::valid_uuid(std::string_view(text(o,"device_uri")).substr(15)) && hex(text(o,"plan_digest"),64) && operation(text(o,"operation")));
    const auto& c = o.at("config").as<json::object>();
    keys(c,{"profile","attestation_mode","domain_name","service_name","feature_source","signing_thumbprint","encryption_thumbprint","dsrm_secret_ref","join_secret_ref","allow_reboot","node_role","primary_server"});
    const auto& profile=text(c,"profile"); const auto& mode=text(c,"attestation_mode");
    require((profile=="vtpm" || profile=="shielded") && (mode=="host_key" || mode=="tpm") && (profile!="shielded" || mode=="tpm"));
    require(dns(text(c,"domain_name")) && label(text(c,"service_name")) && source_path(text(c,"feature_source")));
    require(hex(text(c,"signing_thumbprint"),40,true) && hex(text(c,"encryption_thumbprint"),40,true));
    require(text(c,"signing_thumbprint")!=text(c,"encryption_thumbprint"));
    require(reference(text(c,"dsrm_secret_ref")) && reference(text(c,"join_secret_ref"),true));
    (void)flag(c,"allow_reboot");
    const auto& role=text(c,"node_role"); const auto& address=text(c,"primary_server");
    require(role=="primary" || role=="additional");
    // Native provider performs InetPton before using an additional-node address.
    require(role=="primary" ? address.empty() : (!text(c,"join_secret_ref").empty() && !address.empty() && address.size()<=45 && std::all_of(address.begin(),address.end(),[](unsigned char v){return std::isxdigit(v)||v=='.'||v==':';})));
    require(text(o,"operation")!="create_forest" || role=="primary");
    require(text(o,"operation")!="join_node" || role=="additional");
    require(o.at("expires_at").as<std::int64_t>()>0);
    return {o};
  } catch (...) { throw error("hgs_contract_invalid"); }
}
bool unexpired(const job& j,std::int64_t now) { return j.fields.at("expires_at").as<std::int64_t>()>now; }
bool bound_to(const job& j,std::string_view uri) { return j.text("device_uri")==uri; }
void validate_observation(const json::object& o) {
  try {
    keys(o,{"os_build","is_server","computer_name","domain_name","domain_joined","domain_role","role_installed","service_initialized","attestation_mode","signing_certificate_ready","encryption_certificate_ready","feature_source_ready","dsrm_secret_ready","join_secret_ready","reboot_pending","boot_id","service_healthy","key_access_verified","mode_supported","offline_source_policy_ready","configured_service_name","configured_signing_thumbprint","configured_encryption_thumbprint"});
    for (const auto k : {"is_server","domain_joined","role_installed","service_initialized","signing_certificate_ready","encryption_certificate_ready","feature_source_ready","dsrm_secret_ready","join_secret_ready","reboot_pending","service_healthy","key_access_verified","mode_supported","offline_source_policy_ready"}) (void)flag(o,k);
    require(safe_text(text(o,"os_build"),12) && safe_text(text(o,"computer_name"),63) && safe_text(text(o,"domain_name"),253,true) && safe_text(text(o,"boot_id"),64));
    const auto role=o.at("domain_role").as<std::int64_t>(); require(role>=0 && role<=5);
    const auto& mode=text(o,"attestation_mode");require(mode=="none" || mode=="host_key" || mode=="tpm");
    require(safe_text(text(o,"configured_service_name"),253,true));
    for(const auto key:{"configured_signing_thumbprint","configured_encryption_thumbprint"})require(text(o,key).empty() || hex(text(o,key),40,true));
  } catch (...) { throw error("hgs_observation_invalid"); }
}
json::object result(std::string_view status,std::string_view code,json::object observed) {
  json::object r{{"status",status},{"result_code",code},{"observation",std::move(observed)}}; validate_result(r); return r;
}
void validate_result(const json::object& r) {
  keys(r,{"status","result_code","observation"});
  const auto& status=text(r,"status");require(status=="succeeded" || status=="failed" || status=="reconciliation_required" || status=="reboot_required");
  const std::set<std::string> codes{"hgs_inspected","hgs_verified","hgs_step_succeeded","hgs_reboot_required","hgs_reboot_observed","hgs_job_expired","hgs_authority_lost","hgs_prerequisite_failed","hgs_provider_failed","hgs_postcondition_failed","hgs_reconciliation_required","hgs_unsupported_platform"};
  require(codes.contains(text(r,"result_code")));
  const auto& o=r.at("observation").as<json::object>();if(!o.empty())validate_observation(o);
  require(!o.empty() || (status=="failed" || status=="reconciliation_required"));
}
bool prerequisites(const job& j,const json::object& o) {
  validate_observation(o);const auto& c=j.config();const auto& op=j.text("operation");
  if (op=="inspect") return true;
  if (!flag(o,"is_server") || (text(o,"os_build")!="20348" && text(o,"os_build")!="26100") || !flag(o,"mode_supported"))return false;
  if (flag(o,"service_initialized") && text(o,"attestation_mode")!=text(c,"attestation_mode"))return false;
  if (flag(o,"service_initialized") && (op=="initialize" || op=="verify") &&
      (text(o,"configured_service_name")!=text(c,"service_name") || text(o,"configured_signing_thumbprint")!=text(c,"signing_thumbprint") || text(o,"configured_encryption_thumbprint")!=text(c,"encryption_thumbprint")))return false;
  if (op=="reboot")return !flag(o,"reboot_pending") || flag(c,"allow_reboot");
  if (op=="install_role")return flag(o,"feature_source_ready") && flag(o,"offline_source_policy_ready") && !flag(o,"domain_joined");
  if (flag(o,"reboot_pending"))return false;
  if (op=="create_forest" || op=="join_node")return flag(o,"role_installed") && !flag(o,"domain_joined") && flag(o,"dsrm_secret_ready") && (op!="join_node" || flag(o,"join_secret_ready"));
  return flag(o,"role_installed") && flag(o,"domain_joined") && text(o,"domain_name")==text(c,"domain_name") && o.at("domain_role").as<std::int64_t>()>=4 && flag(o,"signing_certificate_ready") && flag(o,"encryption_certificate_ready");
}
bool postcondition(const job& j,const json::object& before,const json::object& after) {
  validate_observation(after);const auto& op=j.text("operation");const auto& c=j.config();
  if(op=="inspect")return true;
  if(op=="reboot")return !before.empty() && text(before,"boot_id")!=text(after,"boot_id") && !flag(after,"reboot_pending");
  if(op=="install_role")return flag(after,"role_installed");
  if(op=="create_forest" || op=="join_node")return flag(after,"domain_joined") && text(after,"domain_name")==text(c,"domain_name") && after.at("domain_role").as<std::int64_t>()>=4;
  return flag(after,"role_installed") && flag(after,"service_initialized") && text(after,"attestation_mode")==text(c,"attestation_mode") &&
      flag(after,"domain_joined") && text(after,"domain_name")==text(c,"domain_name") && after.at("domain_role").as<std::int64_t>()>=4 && !flag(after,"reboot_pending") && flag(after,"signing_certificate_ready") && flag(after,"encryption_certificate_ready") &&
      text(after,"configured_service_name")==text(c,"service_name") && text(after,"configured_signing_thumbprint")==text(c,"signing_thumbprint") && text(after,"configured_encryption_thumbprint")==text(c,"encryption_thumbprint") && flag(after,"key_access_verified") &&
      (op!="verify" || (flag(after,"service_healthy") && flag(after,"key_access_verified") && !flag(after,"reboot_pending")));
}
json::object journal_document(const journal& j) {
  const auto state=j.state==phase::prepared?"prepared":j.state==phase::claiming?"claiming":j.state==phase::intent?"intent":j.state==phase::reboot_wait?"reboot_wait":"terminal";
  return {{"schema_version",1},{"assignment",j.assignment.fields},{"state",state},{"before",j.before},{"outcome",j.outcome}};
}
journal parse_journal(const json::value& v) {
  const auto& o=v.as<json::object>();keys(o,{"schema_version","assignment","state","before","outcome"});require(o.at("schema_version").as<std::int64_t>()==1);
  const auto& s=text(o,"state");require(s=="prepared"||s=="claiming"||s=="intent"||s=="reboot_wait"||s=="terminal");
  journal j{parse_job(o.at("assignment")),s=="prepared"?phase::prepared:s=="claiming"?phase::claiming:s=="intent"?phase::intent:s=="reboot_wait"?phase::reboot_wait:phase::terminal,o.at("before").as<json::object>(),o.at("outcome").as<json::object>()};
  if(!j.before.empty())validate_observation(j.before);if(!j.outcome.empty())validate_result(j.outcome);
  require(j.state==phase::prepared || !j.before.empty() || j.state==phase::terminal);require(j.state!=phase::terminal || !j.outcome.empty());return j;
}
bool release_matches(const journal& fenced,const json::object& release) {
  try {
    keys(release,{"job_id","plan_digest"});
    return fenced.state==phase::terminal && text(fenced.outcome,"status")=="reconciliation_required" &&
      text(release,"job_id")==fenced.assignment.text("job_id") && text(release,"plan_digest")==fenced.assignment.text("plan_digest");
  }catch(...){return false;}
}
bool permitted_while_fenced(const journal& fenced,const job& offered) {
  return offered.text("operation")=="inspect" && offered.text("tenant_id")==fenced.assignment.text("tenant_id") &&
      offered.text("enrollment_id")==fenced.assignment.text("enrollment_id") && offered.text("device_uri")==fenced.assignment.text("device_uri");
}
json::object recover(journal& j,provider& local,const persist& save) {
  if(j.state==phase::terminal)return j.outcome;
  // A recovered prepared record proves that neither claim nor provider apply
  // began. Retire it explicitly so cancellation or a replacement offer cannot
  // strand the worker on stale non-executed intent.
  if(j.state==phase::prepared)return finish(j,save,"failed",unexpired(j.assignment)?"hgs_authority_lost":"hgs_job_expired",j.before);
  if(j.state==phase::claiming)return finish(j,save,"failed","hgs_authority_lost",j.before);
  require(j.state==phase::intent || j.state==phase::reboot_wait);
  try {
    auto after=local.inspect(j.assignment);validate_observation(after);
    if(postcondition(j.assignment,j.before,after)) {
      if(read_only(j.assignment))return finish(j,save,"succeeded",j.assignment.text("operation")=="inspect"?"hgs_inspected":"hgs_verified",std::move(after));
      const bool pending=flag(after,"reboot_pending");
      return finish(j,save,pending?"reboot_required":"succeeded",j.assignment.text("operation")=="reboot"?"hgs_reboot_observed":"hgs_step_succeeded",std::move(after));
    }
    if(j.state==phase::reboot_wait && unexpired(j.assignment) && text(after,"boot_id")==text(j.before,"boot_id")) {
      j.outcome=result("reboot_required","hgs_reboot_required",std::move(after));save(j);return j.outcome;
    }
    return finish(j,save,read_only(j.assignment)?"failed":"reconciliation_required",read_only(j.assignment)?"hgs_postcondition_failed":"hgs_reconciliation_required",std::move(after));
  } catch(...) { return finish(j,save,read_only(j.assignment)?"failed":"reconciliation_required",read_only(j.assignment)?"hgs_provider_failed":"hgs_reconciliation_required"); }
}
json::object execute(journal& j,provider& local,const persist& save,const std::function<bool()>& claim,const std::function<bool()>& authority) {
  if(j.state==phase::terminal)return j.outcome;
  if(j.state!=phase::prepared)return recover(j,local,save);
  if(!unexpired(j.assignment))return finish(j,save,"failed","hgs_job_expired");
  try {
    j.before=local.inspect(j.assignment);validate_observation(j.before);
    if(!prerequisites(j.assignment,j.before))return finish(j,save,"failed","hgs_prerequisite_failed",j.before);
    if(!authority())return finish(j,save,"failed","hgs_authority_lost",j.before);
    j.state=phase::claiming;save(j);
    if(!claim() || !authority() || !unexpired(j.assignment))return finish(j,save,"failed","hgs_authority_lost",j.before);
    j.state=phase::intent;save(j);
    if(!authority() || !unexpired(j.assignment))return finish(j,save,"failed","hgs_authority_lost",j.before);
    if(read_only(j.assignment)) {
      auto after=local.inspect(j.assignment);
      if(!postcondition(j.assignment,j.before,after))return finish(j,save,"failed","hgs_postcondition_failed",std::move(after));
      return finish(j,save,"succeeded",j.assignment.text("operation")=="inspect"?"hgs_inspected":"hgs_verified",std::move(after));
    }
    if(j.assignment.text("operation")=="reboot" && !flag(j.before,"reboot_pending"))return finish(j,save,"succeeded","hgs_step_succeeded",j.before);
    if(j.assignment.text("operation")=="initialize" && postcondition(j.assignment,{},j.before))return finish(j,save,"succeeded","hgs_step_succeeded",j.before);
    local.apply(j.assignment);
    if(j.assignment.text("operation")=="reboot") {
      j.state=phase::reboot_wait;j.outcome=result("reboot_required","hgs_reboot_required",j.before);save(j);return j.outcome;
    }
    auto after=local.inspect(j.assignment);
    if((j.assignment.text("operation")=="install_role" || j.assignment.text("operation")=="create_forest" || j.assignment.text("operation")=="join_node") && flag(after,"reboot_pending"))
      return finish(j,save,"reboot_required","hgs_reboot_required",std::move(after));
    if(!postcondition(j.assignment,j.before,after))return finish(j,save,"reconciliation_required","hgs_postcondition_failed",std::move(after));
    const bool pending=flag(after,"reboot_pending");return finish(j,save,pending?"reboot_required":"succeeded",pending?"hgs_reboot_required":"hgs_step_succeeded",std::move(after));
  } catch(...) {
    const bool uncertain=j.state==phase::intent && !read_only(j.assignment);
    return finish(j,save,uncertain?"reconciliation_required":"failed",uncertain?"hgs_reconciliation_required":j.state==phase::claiming?"hgs_authority_lost":"hgs_provider_failed");
  }
}
}  // namespace ipms::agent::hgs
