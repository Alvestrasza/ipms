// File Name: gpo_management.cpp
// Version: v0.2.1 | Created: 2026-09-14 | Last Modified: 2026-09-16
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Validate pinned pilot inputs, artifact bytes and non-retryable native write ordering.
#include "ipms/agent/gpo_management.hpp"
#include "ipms/agent/gpo_managed.hpp"
#include "ipms/agent/gpo_override.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <set>
#include <stdexcept>

namespace ipms::agent::gpo {
namespace {
[[noreturn]] void invalid() { throw operation_error("gpo_invalid_job"); }
bool digest(std::string_view s) { return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }); }
bool dns(std::string_view s) {
  if (s.empty() || s.size() > 253 || s.find('.') == s.npos) return false;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= s.size(); ++i) if (i == s.size() || s[i] == '.') {
    if (i == start || i - start > 63 || s[start] == '-' || s[i - 1] == '-') return false;
    start = i + 1;
  } else if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '-')) return false;
  return true;
}
bool clean(std::string_view s, std::size_t limit) { return !s.empty() && s.size() <= limit &&
  std::none_of(s.begin(), s.end(), [](unsigned char c) { return c < 32 || c == 127; }); }
bool principal(std::string_view s) {
  constexpr std::string_view maximum = "9223372036854775807";
  return !s.empty() && s.size() <= maximum.size() && s.front() >= '1' && s.front() <= '9' &&
      std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; }) &&
      (s.size() < maximum.size() || s <= maximum);
}
std::chrono::system_clock::time_point expiry(std::string_view s) {
  if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z') invalid();
  auto num = [&](std::size_t i, std::size_t n) { unsigned v = 0; for (; n; --n, ++i) {
    if (s[i] < '0' || s[i] > '9') invalid(); v = v * 10 + static_cast<unsigned>(s[i] - '0'); } return v; };
  const auto y = num(0,4), m = num(5,2), d = num(8,2), h = num(11,2), min = num(14,2), sec = num(17,2);
  const std::chrono::year_month_day day{std::chrono::year(static_cast<int>(y)), std::chrono::month(m), std::chrono::day(d)};
  if (!day.ok() || y < 2020 || y > 2100 || h > 23 || min > 59 || sec > 59) invalid();
  return std::chrono::sys_days(day) + std::chrono::hours(h) + std::chrono::minutes(min) + std::chrono::seconds(sec);
}
bool known_code(std::string_view code) {
  constexpr std::string_view codes[]{"gpo_staged_unlinked", "gpo_local_approval_required", "gpo_job_expired",
    "gpo_invalid_job", "gpo_unsupported_component", "gpo_identity_mismatch", "gpo_not_writable_dc",
    "gpo_domain_identity_unavailable", "gpmc_unavailable", "gpo_permission_denied", "gpo_name_collision",
    "gpo_source_mismatch", "gpo_artifact_invalid", "gpo_local_approval_invalid", "gpo_reconciliation_required",
    "gpo_provider_failed", "gpo_verification_failed", "gpo_worker_timeout", "gpo_worker_failed",
    "gpo_journal_invalid", "gpo_claim_uncertain", "gpo_authority_expired", "gpo_enrollment_changed",
    "gpo_portal_approval_required", "gpo_portal_approval_invalid",
    "gpo_inspected", "gpo_prepared", "gpo_linked", "gpo_activated", "gpo_deactivated",
    "gpo_state_changed", "gpo_requires_disabled", "gpo_unmanaged_target", "gpo_target_invalid",
    "gpo_link_conflict", "gpo_backup_failed", "gpo_preflight_required",
    "gpo_preflight_inventory_failed", "gpo_preflight_controller_failed", "gpo_preflight_directory_failed",
    "gpo_preflight_domain_visibility_failed", "gpo_preflight_domain_search_failed",
    "gpo_preflight_site_visibility_failed", "gpo_preflight_site_search_failed", "gpo_preflight_census_mismatch",
    "gpo_preflight_domain_open_failed", "gpo_preflight_domain_identity_failed", "gpo_preflight_domain_query_failed",
    "gpo_preflight_domain_links_failed", "gpo_preflight_domain_merge_failed"};
  return std::find(std::begin(codes), std::end(codes), code) != std::end(codes);
}
}  // namespace

// FIPS 180-4 SHA-256. This portable implementation keeps canonical contract
// hashing identical in Windows and Linux unit tests; known vectors test it.
std::string sha256(std::span<const std::uint8_t> bytes) {
  constexpr std::array<std::uint32_t,64> k{0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  std::array<std::uint32_t,8> h{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  std::vector<std::uint8_t> padded(bytes.begin(), bytes.end());
  const auto bits = static_cast<std::uint64_t>(bytes.size()) * 8;
  padded.push_back(0x80); while (padded.size() % 64 != 56) padded.push_back(0);
  for (int shift = 56; shift >= 0; shift -= 8) padded.push_back(static_cast<std::uint8_t>(bits >> shift));
  for (std::size_t offset = 0; offset < padded.size(); offset += 64) {
    std::array<std::uint32_t,64> w{};
    for (std::size_t i = 0; i < 16; ++i) for (std::size_t j = 0; j < 4; ++j) w[i] = (w[i] << 8) | padded[offset + 4*i+j];
    for (std::size_t i = 16; i < 64; ++i) {
      const auto s0 = std::rotr(w[i-15],7) ^ std::rotr(w[i-15],18) ^ (w[i-15] >> 3);
      const auto s1 = std::rotr(w[i-2],17) ^ std::rotr(w[i-2],19) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    auto [a,b,c,d,e,f,g,hh] = h;
    for (std::size_t i = 0; i < 64; ++i) {
      const auto t1 = hh + (std::rotr(e,6)^std::rotr(e,11)^std::rotr(e,25)) + ((e&f)^(~e&g)) + k[i] + w[i];
      const auto t2 = (std::rotr(a,2)^std::rotr(a,13)^std::rotr(a,22)) + ((a&b)^(a&c)^(b&c));
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }
  constexpr char hex[] = "0123456789abcdef";
  std::string output; output.reserve(64);
  for (const auto v : h) for (int shift = 28; shift >= 0; shift -= 4) output.push_back(hex[(v >> shift)&15]);
  return output;
}
std::string sha256(std::string_view s) { return sha256({reinterpret_cast<const std::uint8_t*>(s.data()),s.size()}); }
bool valid_uuid(std::string_view s) {
  if (s.size() != 36) return false; bool nonzero = false;
  for (std::size_t i=0;i<s.size();++i) {
    if (i==8 || i==13 || i==18 || i==23) { if(s[i]!='-') return false; }
    else { if (!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return false; nonzero |= s[i]!='0'; }
  }
  return nonzero;
}
bool protected_gpo(std::string_view s) {
  if (s.size()==38 && s.front()=='{' && s.back()=='}') s=s.substr(1,36);
  std::string lower(s); for(auto& c:lower) if(c>='A'&&c<='F') c=static_cast<char>(c-'A'+'a');
  return lower=="31b2f340-016d-11d2-945f-00c04fb984f9" || lower=="6ac1786c-016f-11d2-945f-00c04fb984f9";
}
std::string input_digest(json::object document) { document.erase("input_digest"); return sha256(json::serialize(document)); }
job parse_job(const json::value& value) {
  const auto& f=value.as<json::object>();
  constexpr const char* keys[]{"schema","job_id","input_digest","operation","domain_dns_name","domain_guid","forest_dns_name",
    "executor_dc_fqdn","scope_id","scope_revision","target_tier","baseline_id","profile","backup_id","artifact_sha256","pilot_display_name","expires_at"};
  const auto schema=f.at("schema").as<std::int64_t>();
  if((schema!=1&&schema!=2&&schema!=3&&schema!=4)||f.size()!=std::size(keys)+(schema==1?0:schema==2?1:schema==3?11:15)) invalid();
  for(const auto* key:keys) if(!f.contains(key)) invalid();
  if(schema==2&&f.at("approval_mode").as<std::string>()!="portal") invalid();
  job j{f};
  if(j.number("scope_revision")<1 || j.number("target_tier")<0 || j.number("target_tier")>2 ||
      (schema<3&&j.text("operation")!="create_unlinked_pilot") || !valid_uuid(j.text("job_id")) || !valid_uuid(j.text("scope_id")) ||
      !valid_uuid(j.text("domain_guid")) || !dns(j.text("domain_dns_name")) || !dns(j.text("forest_dns_name")) ||
      !dns(j.text("executor_dc_fqdn")) || !digest(j.text("input_digest")) || !digest(j.text("artifact_sha256")) ||
      !clean(j.text("baseline_id"),128) || !clean(j.text("pilot_display_name"),240)) invalid();
  if(j.text("profile")!="server" && j.text("profile")!="client" && j.text("profile")!="domain-controller") invalid();
  const auto& id=j.text("backup_id");
  if(id.size()!=38 || id.front()!='{' || id.back()!='}') invalid();
  std::string lower=id.substr(1,36); for(auto& c:lower) { if(c>='a'&&c<='f') invalid(); if(c>='A'&&c<='F') c=static_cast<char>(c-'A'+'a'); }
  if(!valid_uuid(lower) || protected_gpo(id)) invalid();
  if(j.text("pilot_display_name")=="Default Domain Policy" || j.text("pilot_display_name")=="Default Domain Controllers Policy") invalid();
  (void)expiry(j.text("expires_at"));
  if(schema>=3) validate_managed_job(j);
  if(schema==4) validate_override_job(j);
  if(input_digest(f)!=j.text("input_digest")) invalid();
  return j;
}
bool unexpired(const job& j,std::chrono::system_clock::time_point now) { try {
  const auto t=expiry(j.text("expires_at")); return t>now && t<=now+(j.number("schema")>=3?std::chrono::minutes(15):std::chrono::minutes(60));
} catch(...) { return false; } }
json::object local_approval_document(const job& j,std::string_view uri) {
  if(j.number("schema")!=1||!clean(uri,512)) throw operation_error("gpo_local_approval_invalid");
  return {{"schema",1},{"job",j.fields},{"device_uri",uri}};
}
json::object parse_portal_approval(const json::value& value,const job& j,std::string_view uri) {
  try {
    const auto& a=value.as<json::object>();
    constexpr const char* keys[]{"schema","job_id","input_digest","device_uri","domain_guid","target_tier","operation",
      "requested_by","approved_by","approved_at","expires_at","policy_revision","four_eyes_required"};
    if((j.number("schema")<2||j.number("schema")>4)||j.text("approval_mode")!="portal"||a.size()!=std::size(keys)||!clean(uri,512)) invalid();
    for(const auto* key:keys) if(!a.contains(key)) invalid();
    if(a.at("schema").as<std::int64_t>()!=1||a.at("device_uri").as<std::string>()!=uri||
        a.at("policy_revision").as<std::int64_t>()<1||a.at("target_tier").as<std::int64_t>()!=j.number("target_tier")) invalid();
    for(const auto* key:{"job_id","input_digest","domain_guid","operation","expires_at"})
      if(a.at(key).as<std::string>()!=j.text(key)) invalid();
    const auto& requested=a.at("requested_by").as<std::string>();
    const auto& approved=a.at("approved_by").as<std::string>();
    if(!principal(requested)||!principal(approved)||(a.at("four_eyes_required").as<bool>()&&requested==approved)) invalid();
    const auto approved_at=expiry(a.at("approved_at").as<std::string>()),expires_at=expiry(j.text("expires_at"));
    if(approved_at>=expires_at||approved_at<expires_at-std::chrono::hours(1)) invalid();
    return a;
  } catch(...) { throw operation_error("gpo_portal_approval_invalid"); }
}
bool portal_approval_current(const json::value& a,const job& j,std::string_view uri,std::chrono::system_clock::time_point now) {
  try {const auto parsed=parse_portal_approval(a,j,uri);
    return unexpired(j,now)&&expiry(parsed.at("approved_at").as<std::string>())<=now;
  } catch(...) {return false;}
}
const component_descriptor* component(const job& j) {
  const auto* c=lookup_component(j.text("baseline_id"),j.text("backup_id"));
  return c && c->artifact_sha256==j.text("artifact_sha256") ? c : nullptr;
}
std::vector<std::span<const std::uint8_t>> decode_artifact(const component_descriptor& c,std::span<const std::uint8_t> bytes) {
  auto fail=[] { throw operation_error("gpo_artifact_invalid"); };
  if(bytes.size()<12 || bytes.size()>maximum_artifact_bytes || bytes.size()!=c.artifact_size || c.files.empty() ||
      c.files.size()>maximum_files || std::memcmp(bytes.data(),"IPMSGPO1",8)!=0 || sha256(bytes)!=c.artifact_sha256) fail();
  std::size_t offset=8;
  auto u32=[&] { if(bytes.size()-offset<4) fail(); std::uint32_t v=0; for(unsigned i=0;i<4;++i) v|=static_cast<std::uint32_t>(bytes[offset++])<<(8*i); return v; };
  if(u32()!=c.files.size()) fail();
  std::vector<std::span<const std::uint8_t>> files;
  for(const auto& f:c.files) {
    const auto size=u32(); if(size!=f.bytes || size>maximum_file_bytes || size>bytes.size()-offset) fail();
    const auto content=bytes.subspan(offset,size); if(sha256(content)!=f.sha256) fail();
    files.push_back(content); offset+=size;
  }
  if(offset!=bytes.size()) fail(); return files;
}
std::string_view name(phase p) { switch(p) { case phase::prepared:return "prepared";case phase::granted:return "granted";
  case phase::creating:return "creating";case phase::created:return "created";case phase::importing:return "importing";
  case phase::terminal:return "terminal";case phase::reconciliation:return "reconciliation";} invalid(); }
json::object journal_document(const journal& j) {
  json::object document{{"schema",j.assignment.number("schema")},{"job",j.assignment.fields},{"device_uri",j.device_uri},
    {"phase",name(j.state)},{"gpo_guid",j.gpo_guid},{"grant_deadline_tick",j.grant_deadline_tick},{"result",j.result}};
  if(j.assignment.number("schema")>=2) document.emplace("portal_approval",j.portal_approval);
  else if(!j.portal_approval.get_if<std::nullptr_t>()) invalid();
  return document;
}
journal parse_journal(const json::value& v) {
  const auto& f=v.as<json::object>(); const auto schema=f.at("schema").as<std::int64_t>();
  if((schema!=1&&schema!=2&&schema!=3&&schema!=4)||f.size()!=(schema>=2?8:7)) invalid();
  journal j{parse_job(f.at("job")),f.at("device_uri").as<std::string>()};
  if(j.assignment.number("schema")!=schema) invalid();
  if(schema>=2) {
    j.portal_approval=f.at("portal_approval");
    if(!j.portal_approval.get_if<std::nullptr_t>()) (void)parse_portal_approval(j.portal_approval,j.assignment,j.device_uri);
  }
  bool matched=false; for(const auto p:{phase::prepared,phase::granted,phase::creating,phase::created,phase::importing,phase::terminal,phase::reconciliation})
    if(f.at("phase").as<std::string>()==name(p)) { j.state=p; matched=true; }
  j.gpo_guid=f.at("gpo_guid").as<std::string>(); const auto tick=f.at("grant_deadline_tick").as<std::int64_t>();
  if(!matched || !clean(j.device_uri,512) || tick<0 || (!j.gpo_guid.empty()&&(!valid_uuid(j.gpo_guid)||protected_gpo(j.gpo_guid)))) invalid();
  j.grant_deadline_tick=static_cast<std::uint64_t>(tick); j.result=f.at("result");
  if((j.state==phase::prepared||j.state==phase::granted||j.state==phase::creating)&&!j.gpo_guid.empty()) invalid();
  if(j.state==phase::prepared&&j.grant_deadline_tick!=0) invalid();
  if(schema>=2) {
    const bool approved=!j.portal_approval.get_if<std::nullptr_t>();
    if(approved!=(j.grant_deadline_tick>0)||(approved&&j.state==phase::prepared)) invalid();
    if(!approved&&(j.state==phase::creating||j.state==phase::created||j.state==phase::importing)) invalid();
  }
  if((j.state==phase::created||j.state==phase::importing)&&j.gpo_guid.empty()) invalid();
  const bool completed=j.state==phase::terminal||j.state==phase::reconciliation;
  if(completed ? !valid_result(j.result) : !j.result.get_if<std::nullptr_t>()) invalid();
  if(completed) {
    const auto& receipt=j.result.as<json::object>();const auto status=receipt.at("status").as<std::string>();
    if(schema>=2&&(status=="staged"||status=="linked"||status=="activated"||status=="deactivated")&&j.portal_approval.get_if<std::nullptr_t>()) invalid();
    if(j.state==phase::reconciliation ? status!="requires_reconciliation" : status!="staged"&&status!="failed"&&status!="inspected"&&status!="linked"&&status!="activated"&&status!="deactivated") invalid();
    if(schema<3&&(status=="inspected"||status=="linked"||status=="activated"||status=="deactivated")) invalid();
    if(schema<3&&receipt.at("evidence").get_if<json::object>()&&receipt.at("evidence").as<json::object>().contains("schema")) invalid();
    if(schema>=3&&status!="failed"&&status!="requires_reconciliation") {
      if(!valid_managed_result(receipt)) invalid();
      const auto& e=receipt.at("evidence").as<json::object>();
      if(e.at("schema").as<std::int64_t>()!=schema||(schema==4&&e.at("override_sha256").as<std::string>()!=j.assignment.text("override_sha256"))) invalid();
      if(e.at("operation").as<std::string>()!=j.assignment.text("operation")||e.at("managed_id").as<std::string>()!=j.assignment.text("managed_id")) invalid();
      if((status=="staged"||status=="activated"||j.assignment.text("operation")=="import_and_link_managed_gpo")&&e.at("prepared_artifact_sha256").as<std::string>()!=j.assignment.text("artifact_sha256")) invalid();
    }
    if(status=="inspected"&&!inspection(j.assignment)) invalid();
    if(inspection(j.assignment)&&status!="inspected"&&status!="failed") invalid();
    const auto* id=receipt.at("gpo_guid").get_if<std::string>();if((id?*id:std::string{})!=j.gpo_guid) invalid();
  }
  return j;
}
json::object portal_approval_receipt(const journal& j) {
  if((j.assignment.number("schema")<2||j.assignment.number("schema")>4)||inspection(j.assignment)||j.state!=phase::granted||j.grant_deadline_tick==0||!j.gpo_guid.empty()||
      !j.result.get_if<std::nullptr_t>()) throw operation_error("gpo_portal_approval_invalid");
  const auto approved=parse_portal_approval(j.portal_approval,j.assignment,j.device_uri);
  return {{"schema",1},{"purpose","portal_gpo_claim"},{"job",j.assignment.fields},{"device_uri",j.device_uri},
    {"approval",approved},{"grant_deadline_tick",j.grant_deadline_tick}};
}
bool grant_current(const journal& j,std::uint64_t now_tick) {
  return j.grant_deadline_tick>now_tick&&j.grant_deadline_tick-now_tick<=15'000;
}
json::object result(std::string_view status,std::string_view code,std::string_view guid,json::value evidence) {
  json::object r{{"status",status},{"result_code",code},{"gpo_guid",guid.empty()?json::value{}:json::value(guid)},{"evidence",std::move(evidence)}};
  if(!valid_result(r)) invalid(); return r;
}
bool valid_result(const json::value& v) { try {
  const auto& f=v.as<json::object>(); if(f.size()!=4 || !known_code(f.at("result_code").as<std::string>())) return false;
  const auto& s=f.at("status").as<std::string>();
  const auto& code=f.at("result_code").as<std::string>();
  if(const auto* evidence=f.at("evidence").get_if<json::object>();evidence&&evidence->contains("schema")&&evidence->at("schema").get_if<std::int64_t>()&&(evidence->at("schema").as<std::int64_t>()==3||evidence->at("schema").as<std::int64_t>()==4)) return valid_managed_result(f);
  if(s!="staged"&&s!="failed"&&s!="awaiting_local_approval"&&s!="awaiting_portal_approval"&&s!="requires_reconciliation") return false;
  const auto* id=f.at("gpo_guid").get_if<std::string>(); if(id&&(!valid_uuid(*id)||protected_gpo(*id))) return false;
  if(!id&&!f.at("gpo_guid").get_if<std::nullptr_t>()) return false;
  if(s=="staged") { const auto& e=f.at("evidence").as<json::object>(); return id && e.size()==6 &&
    f.at("result_code").as<std::string>()=="gpo_staged_unlinked" && !e.at("computer_enabled").as<bool>() && !e.at("user_enabled").as<bool>() &&
    e.at("unlinked").as<bool>() && dns(e.at("domain_dns_name").as<std::string>()) && valid_uuid(e.at("domain_guid").as<std::string>()) && dns(e.at("dc_fqdn").as<std::string>()); }
  if(code=="gpo_inspected"||code=="gpo_prepared"||code=="gpo_linked"||code=="gpo_activated"||code=="gpo_deactivated"||code=="gpo_staged_unlinked" || (s=="awaiting_local_approval"&&code!="gpo_local_approval_required") ||
      (s=="awaiting_portal_approval"&&code!="gpo_portal_approval_required"))return false;
  return f.at("evidence").get_if<std::nullptr_t>() && (s=="requires_reconciliation" || !id);
} catch(...) { return false; } }
bool executor_matches(const job& j,const json::object& e) { try { return e.at("role").as<std::string>()=="writable-domain-controller" &&
  e.at("gpmc_available").as<bool>() && e.at("domain_dns_name").as<std::string>()==j.text("domain_dns_name") &&
  e.at("domain_guid").as<std::string>()==j.text("domain_guid") && e.at("forest_dns_name").as<std::string>()==j.text("forest_dns_name") &&
  e.at("dc_fqdn").as<std::string>()==j.text("executor_dc_fqdn"); } catch(...) { return false; } }
bool record_claim(journal& j,const json::value& reply,std::uint64_t deadline,const persist& save,
    const json::value& expected_approval,std::chrono::system_clock::time_point now) {
  if(!save||j.state!=phase::granted||j.grant_deadline_tick!=0||!j.gpo_guid.empty()||!j.result.get_if<std::nullptr_t>()||
      !j.portal_approval.get_if<std::nullptr_t>()||deadline==0)
    throw operation_error("gpo_journal_invalid");
  const auto& claim=reply.as<json::object>();
  const bool authorized=claim.at("authorized").as<bool>();const auto& mode=claim.at("mode").as<std::string>();
  const bool portal=j.assignment.number("schema")>=2;
  if(inspection(j.assignment)) invalid();
  if(claim.size()!=(portal&&authorized&&mode=="execute"?4:3)||parse_job(claim.at("job"))!=j.assignment) invalid();
  if(!portal&&!expected_approval.get_if<std::nullptr_t>()) throw operation_error("gpo_local_approval_invalid");
  if(authorized&&mode=="execute") {
    if(portal) {
      const auto approved=parse_portal_approval(claim.at("approval"),j.assignment,j.device_uri);
      if(json::value(approved)!=expected_approval||!portal_approval_current(approved,j.assignment,j.device_uri,now))
        throw operation_error("gpo_portal_approval_invalid");
      j.portal_approval=approved;
    }
    j.grant_deadline_tick=deadline;save(j);return true;
  }
  if(!authorized&&mode=="cancelled") {
    j.state=phase::terminal;j.result=result("failed","gpo_authority_expired");
  }else {
    j.state=phase::reconciliation;j.result=result("requires_reconciliation","gpo_claim_uncertain");
  }
  save(j);return false;
}
json::object execute_pilot(journal& j,pilot_provider& provider,const persist& save,const std::function<bool()>& authority,
    const std::function<void()>& consume) {
  if(!save||!authority||!consume) throw operation_error("gpo_journal_invalid");
  if(j.assignment.number("schema")>=3) throw operation_error("gpo_invalid_job");
  if(j.state!=phase::granted) {
    if((j.state==phase::terminal||j.state==phase::reconciliation)&&valid_result(j.result)) return j.result.as<json::object>();
    return result("requires_reconciliation","gpo_reconciliation_required",j.gpo_guid);
  }
  bool invoked=false;
  try {
    if(j.assignment.number("schema")>=2) (void)portal_approval_receipt(j);
    if(!authority()) throw operation_error("gpo_authority_expired");
    provider.preflight(); if(!authority()) throw operation_error("gpo_authority_expired");
    consume(); j.state=phase::creating; save(j);
    if(!authority()) throw operation_error("gpo_authority_expired");
    invoked=true; const auto created_id=provider.create();
    if(!valid_uuid(created_id)||protected_gpo(created_id)) throw operation_error("gpo_verification_failed");
    j.gpo_guid=created_id;
    j.state=phase::created; save(j);
    provider.disable(j.gpo_guid); provider.identify(j.gpo_guid);
    j.state=phase::importing; save(j); provider.import_settings(j.gpo_guid);
    provider.disable(j.gpo_guid); auto evidence=provider.verify(j.gpo_guid);
    auto r=result("staged","gpo_staged_unlinked",j.gpo_guid,std::move(evidence));
    j.state=phase::terminal; j.result=r; save(j); return r;
  } catch(const std::exception& error) {
    const std::string code=known_code(error.what())?error.what():"gpo_provider_failed";
    // A durable creating intent is ambiguous after recovery even if this process
    // knows it did not enter CreateGPO. Conservatively retain that fence.
    const bool uncertain=invoked||j.state==phase::creating||j.state==phase::created||j.state==phase::importing;
    if(uncertain) { auto r=result("requires_reconciliation",code,j.gpo_guid); j.state=phase::reconciliation; j.result=r; save(j); return r; }
    auto r=result("failed",code); j.state=phase::terminal; j.result=r; save(j); return r;
  }
}
}  // namespace ipms::agent::gpo
