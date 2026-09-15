// File Name: windows_gpo_managed.cpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Exact-DC ADSI inspection and bounded native managed GPO lifecycle.
#include "ipms/agent/windows_gpo_management.hpp"
#include "ipms/agent/gpo_managed.hpp"
#include <windows.h>
#include <ole2.h>
#include <activeds.h>
#include <gpmgmt.h>
#include <dsgetdc.h>
#include <lm.h>
#include <winldap.h>
#include <winber.h>
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <set>
#include <tuple>

namespace ipms::agent::windows {
namespace {
namespace json=gpo::json;
using Microsoft::WRL::ComPtr;
[[noreturn]] void fail(const char* code="gpo_provider_failed") {throw gpo::operation_error(code);}
void check(HRESULT hr) {if(FAILED(hr))fail(hr==E_ACCESSDENIED||hr==HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)?"gpo_permission_denied":"gpo_provider_failed");}
std::wstring wide(std::string_view s) {
  if(s.empty())return {};const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
  if(!n)fail();std::wstring out(n,L'\0');if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n)!=n)fail();return out;
}
std::string utf8(std::wstring_view s) {
  if(s.empty())return {};const auto n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
  if(!n)fail();std::string out(n,'\0');if(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr)!=n)fail();return out;
}
std::string lower(std::string s) {for(auto& c:s)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');return s;}
std::string guid(std::string s) {
  if(s.size()==38&&s.front()=='{'&&s.back()=='}')s=s.substr(1,36);s=lower(std::move(s));if(!gpo::valid_uuid(s))fail("gpo_target_invalid");return s;
}
struct bstr {
  BSTR value{};explicit bstr(std::wstring_view s):value(SysAllocStringLen(s.data(),static_cast<UINT>(s.size()))){if(!value)fail();}
  explicit bstr(std::string_view s):bstr(wide(s)){}~bstr(){SysFreeString(value);}bstr(const bstr&)=delete;
};
struct variant {VARIANT value{};~variant(){VariantClear(&value);}variant()=default;variant(const variant&)=delete;};
template<class F> std::string property(F getter) {BSTR raw{};const auto hr=getter(&raw);struct release{BSTR p;~release(){SysFreeString(p);}}r{raw};check(hr);return raw?utf8({raw,SysStringLen(raw)}):std::string{};}
template<class T> ComPtr<T> dispatch(VARIANT& value) {
  ComPtr<T> out;IUnknown* unknown=value.vt==VT_DISPATCH?value.pdispVal:value.vt==VT_UNKNOWN?value.punkVal:nullptr;
  if(!unknown)fail();check(unknown->QueryInterface(IID_PPV_ARGS(&out)));return out;
}
template<class T,class C> std::vector<ComPtr<T>> items(C* collection,std::size_t bound) {
  long count{};check(collection->get_Count(&count));if(count<0||static_cast<std::size_t>(count)>bound)fail("gpo_target_invalid");
  std::vector<ComPtr<T>> out;for(long i=1;i<=count;++i){variant v;check(collection->get_Item(i,&v.value));out.push_back(dispatch<T>(v.value));}return out;
}
std::string object_text(IADs* ads,const wchar_t* name) {bstr key{std::wstring_view(name)};variant v;check(ads->Get(key.value,&v.value));if(v.value.vt!=VT_BSTR||!v.value.bstrVal)fail("gpo_target_invalid");return utf8({v.value.bstrVal,SysStringLen(v.value.bstrVal)});}
ComPtr<IADs> directory_object(const gpo::job& job,std::string_view dn) {
  // DN strings have already passed the fixed OU/domain parser. The server is
  // always the authenticated executor DC, never a received LDAP URL/provider.
  const auto path=wide("LDAP://"+job.text("executor_dc_fqdn")+"/"+std::string(dn));ComPtr<IADs> ads;
  check(ADsOpenObject(path.c_str(),nullptr,nullptr,ADS_SECURE_AUTHENTICATION|ADS_USE_SIGNING|ADS_USE_SEALING|ADS_SERVER_BIND,
    IID_IADs,reinterpret_cast<void**>(ads.GetAddressOf())));return ads;
}
std::string object_guid(IADs* ads) {
  bstr key{std::wstring_view(L"objectGUID")};variant v;check(ads->Get(key.value,&v.value));
  if(v.value.vt!=(VT_ARRAY|VT_UI1)||!v.value.parray||SafeArrayGetDim(v.value.parray)!=1)fail("gpo_target_invalid");
  LONG begin{},end{};check(SafeArrayGetLBound(v.value.parray,1,&begin));check(SafeArrayGetUBound(v.value.parray,1,&end));if(end-begin+1!=16)fail("gpo_target_invalid");
  void* raw{};check(SafeArrayAccessData(v.value.parray,&raw));GUID id{};std::memcpy(&id,raw,sizeof(id));check(SafeArrayUnaccessData(v.value.parray));
  std::array<wchar_t,40> text{};if(!StringFromGUID2(id,text.data(),static_cast<int>(text.size())))fail("gpo_target_invalid");return guid(utf8(text.data()));
}
std::string object_usn(IADs* ads) {
  bstr key{std::wstring_view(L"uSNChanged")};variant v;check(ads->Get(key.value,&v.value));
  if(v.value.vt==VT_BSTR&&v.value.bstrVal)return utf8({v.value.bstrVal,SysStringLen(v.value.bstrVal)});
  auto integer=dispatch<IADsLargeInteger>(v.value);long high{},low{};check(integer->get_HighPart(&high));check(integer->get_LowPart(&low));
  if(high<0)fail("gpo_target_invalid");return std::to_string((static_cast<std::uint64_t>(high)<<32)|static_cast<std::uint32_t>(low));
}
std::string kind(IGPMSOM* som) {GPMSOMType type{};check(som->get_Type(&type));if(type==somOU)return "ou";if(type==somDomain)return "domain";if(type==somSite)return "site";fail("gpo_target_invalid");}
json::object link_state(IGPMGPOLink* link) {
  ComPtr<IGPMSOM> som;check(link->get_SOM(&som));VARIANT_BOOL enabled{},enforced{};long order{};
  check(link->get_Enabled(&enabled));check(link->get_Enforced(&enforced));check(link->get_SOMLinkOrder(&order));
  return {{"guid",guid(property([&](BSTR* p){return link->get_GPOID(p);}))},
    {"domain",lower(property([&](BSTR* p){return link->get_GPODomain(p);}))},
    {"dn",property([&](BSTR* p){return som->get_Path(p);})},{"kind",kind(som.Get())},
    {"enabled",enabled!=VARIANT_FALSE},{"enforced",enforced!=VARIANT_FALSE},{"order",order}};
}
json::array som_links(IGPMSOM* som,bool inherited=false) {
  ComPtr<IGPMGPOLinksCollection> collection;check(inherited?som->GetInheritedGPOLinks(&collection):som->GetGPOLinks(&collection));
  const auto current=lower(property([&](BSTR* p){return som->get_Path(p);}));
  json::array out;for(const auto& link:items<IGPMGPOLink>(collection.Get(),128)) {
    auto state=link_state(link.Get());
    if(inherited&&lower(state.at("dn").as<std::string>())==current)continue;
    out.push_back(std::move(state));
  }return out;
}
std::string guid(const GUID& id) {
  std::array<wchar_t,40> text{};if(!StringFromGUID2(id,text.data(),static_cast<int>(text.size())))fail("gpo_preflight_required");return guid(utf8(text.data()));
}
bool dns_name(std::string_view name) {
  if(name.empty()||name.size()>253||name.find('.')==name.npos)return false;
  std::size_t start{};for(std::size_t n=0;n<=name.size();++n) {
    if(n==name.size()||name[n]=='.'){if(n==start||n-start>63||name[start]=='-'||name[n-1]=='-')return false;start=n+1;}
    else if(!((name[n]>='a'&&name[n]<='z')||(name[n]>='0'&&name[n]<='9')||name[n]=='-'))return false;
  }return true;
}
std::string domain_dn(std::string_view dns) {
  if(!dns_name(dns))fail("gpo_preflight_required");std::string out;std::size_t begin{};
  for(std::size_t n=0;n<=dns.size();++n)if(n==dns.size()||dns[n]=='.'){if(!out.empty())out+=',';out+="dc=";out+=dns.substr(begin,n-begin);begin=n+1;}return out;
}
std::vector<gpo::forest_domain> forest_domains(const gpo::job& job) {
  PDS_DOMAIN_TRUSTSW raw{};ULONG count{};auto server=wide(job.text("executor_dc_fqdn"));
  const auto status=DsEnumerateDomainTrustsW(server.data(),DS_DOMAIN_IN_FOREST|DS_DOMAIN_PRIMARY,&raw,&count);
  struct release{void* p;~release(){if(p)NetApiBufferFree(p);}} lifetime{raw};
  if(status!=ERROR_SUCCESS||!raw||count==0||count>32)fail("gpo_preflight_required");std::vector<gpo::forest_domain> out;
  for(ULONG n=0;n<count;++n) {
    if(!(raw[n].Flags&DS_DOMAIN_IN_FOREST)||!raw[n].DnsDomainName)fail("gpo_preflight_required");
    out.push_back({lower(utf8(raw[n].DnsDomainName)),guid(raw[n].DomainGuid),(raw[n].Flags&DS_DOMAIN_PRIMARY)!=0});
  }
  std::sort(out.begin(),out.end(),[](const auto& a,const auto& b){return a.dns_name<b.dns_name;});
  gpo::validate_forest_domains(job,out);return out;
}
std::string discover_dc(const gpo::job& job,const gpo::forest_domain& domain) {
  if(domain.primary)return job.text("executor_dc_fqdn");
  auto dns=wide(domain.dns_name),server=wide(job.text("executor_dc_fqdn")),id=wide("{"+domain.guid+"}");GUID expected{};
  if(FAILED(CLSIDFromString(id.c_str(),&expected)))fail("gpo_preflight_required");PDOMAIN_CONTROLLER_INFOW raw{};
  const auto status=DsGetDcNameW(server.c_str(),dns.c_str(),&expected,nullptr,
    DS_DIRECTORY_SERVICE_REQUIRED|DS_WRITABLE_REQUIRED|DS_RETURN_DNS_NAME|DS_FORCE_REDISCOVERY,&raw);
  struct release{void* p;~release(){if(p)NetApiBufferFree(p);}} lifetime{raw};
  if(status!=ERROR_SUCCESS||!raw||!raw->DomainControllerName||!raw->DomainName||!raw->DnsForestName||
    !(raw->Flags&DS_DS_FLAG)||!(raw->Flags&DS_WRITABLE_FLAG)||guid(raw->DomainGuid)!=domain.guid||
    lower(utf8(raw->DomainName))!=domain.dns_name||lower(utf8(raw->DnsForestName))!=job.text("forest_dns_name"))fail("gpo_preflight_required");
  auto result=lower(utf8(raw->DomainControllerName));if(result.starts_with("\\\\"))result.erase(0,2);
  if(!dns_name(result))fail("gpo_preflight_required");return result;
}

// A normal search may silently omit ACL-hidden objects/attributes. This
// auxiliary, critical DirSync request uses flags zero, requiring replication
// read visibility rather than LDAP_DIRSYNC_OBJECT_SECURITY. It requests only
// gPLink for this exact GPO DN; no credentials, users or other policy contents.
// There is deliberately no fallback to a security-trimmed search.
class link_visibility_reader {
  LDAP* session_{};
  struct message {LDAPMessage* value{};~message(){if(value)ldap_msgfree(value);}};
  struct controls {LDAPControlW** value{};~controls(){if(value)ldap_controls_freeW(value);}};
  struct ber {BerElement* value{};~ber(){if(value)ber_free(value,1);}};
  struct bytes {BERVAL* value{};~bytes(){if(value)ber_bvfree(value);}};
  static void good(ULONG status){if(status!=LDAP_SUCCESS)fail("gpo_preflight_required");}
  std::string text(LDAPMessage* entry,const wchar_t* attribute) {
    auto values=ldap_get_valuesW(session_,entry,const_cast<wchar_t*>(attribute));
    struct release{wchar_t** p;~release(){if(p)ldap_value_freeW(p);}} lifetime{values};
    if(!values||!values[0]||values[1]||wcslen(values[0])>32768)fail("gpo_preflight_required");return utf8(values[0]);
  }
  void base(std::string_view dn,wchar_t** attributes,message& result) {
    auto path=wide(dn);wchar_t filter[]=L"(objectClass=*)";LDAP_TIMEVAL timeout{5,0};
    good(ldap_search_ext_sW(session_,path.data(),LDAP_SCOPE_BASE,filter,attributes,0,nullptr,nullptr,&timeout,2,&result.value));
    if(ldap_count_entries(session_,result.value)!=1)fail("gpo_preflight_required");
  }
 public:
  std::string naming_context;
  std::string configuration_context;
  link_visibility_reader(const gpo::job& job,const gpo::forest_domain& domain,const std::string& dc) {
    try {
      auto host=wide(dc);session_=ldap_initW(host.data(),LDAP_PORT);if(!session_)fail("gpo_preflight_required");
      ULONG version=LDAP_VERSION3,on=1,off=0;
      good(ldap_set_optionW(session_,LDAP_OPT_PROTOCOL_VERSION,&version));
      good(ldap_set_optionW(session_,LDAP_OPT_SIGN,&on));good(ldap_set_optionW(session_,LDAP_OPT_ENCRYPT,&on));
      good(ldap_set_optionW(session_,LDAP_OPT_REFERRALS,LDAP_OPT_OFF));good(ldap_set_optionW(session_,LDAP_OPT_AUTO_RECONNECT,&off));
      LDAP_TIMEVAL timeout{5,0};good(ldap_connect(session_,&timeout));good(ldap_bind_sW(session_,nullptr,nullptr,LDAP_AUTH_NEGOTIATE));
      ULONG signed_session{},sealed_session{};good(ldap_get_optionW(session_,LDAP_OPT_SIGN,&signed_session));good(ldap_get_optionW(session_,LDAP_OPT_ENCRYPT,&sealed_session));
      if(!signed_session||!sealed_session)fail("gpo_preflight_required");
      wchar_t hostname[]=L"dnsHostName",default_nc[]=L"defaultNamingContext",root_nc[]=L"rootDomainNamingContext",configuration[]=L"configurationNamingContext",synchronized[]=L"isSynchronized";
      wchar_t* attributes[]{hostname,default_nc,root_nc,configuration,synchronized,nullptr};message root;base("",attributes,root);auto entry=ldap_first_entry(session_,root.value);
      naming_context=text(entry,default_nc);configuration_context=text(entry,configuration);
      if(lower(text(entry,hostname))!=dc||lower(naming_context)!=domain_dn(domain.dns_name)||
        lower(text(entry,root_nc))!=domain_dn(job.text("forest_dns_name"))||
        lower(configuration_context)!="cn=configuration,"+domain_dn(job.text("forest_dns_name"))||lower(text(entry,synchronized))!="true")fail("gpo_preflight_required");
      wchar_t object_guid_name[]=L"objectGUID",instance[]=L"instanceType";wchar_t* identity[]{object_guid_name,instance,nullptr};message domain_root;base(naming_context,identity,domain_root);
      entry=ldap_first_entry(session_,domain_root.value);auto values=ldap_get_values_lenW(session_,entry,object_guid_name);
      struct release{BERVAL** p;~release(){if(p)ldap_value_free_len(p);}} lifetime{values};
      if(!values||!values[0]||values[1]||values[0]->bv_len!=sizeof(GUID))fail("gpo_preflight_required");GUID actual{};std::memcpy(&actual,values[0]->bv_val,sizeof(actual));
      if(guid(actual)!=domain.guid||(std::stoul(text(entry,instance))&4)==0)fail("gpo_preflight_required");
    }catch(...){if(session_){ldap_unbind(session_);session_=nullptr;}throw;}
  }
  ~link_visibility_reader(){if(session_)ldap_unbind(session_);}
  link_visibility_reader(const link_visibility_reader&)=delete;
  std::map<std::string,std::uint32_t> links(std::string_view context,std::string_view policy_dn) {
    const auto source=lower(std::string(policy_dn));
    // The source DN is built only from a canonical GUID and validated DNS.
    if(source.find_first_of("*()\\")!=source.npos)fail("gpo_preflight_required");
    auto base_dn=wide(context),filter=wide("(gPLink=*"+source+"*)");std::string cookie;
    std::map<std::string,std::uint32_t> found;std::size_t rows{},total_bytes{};
    for(unsigned page=0;page<32;++page) {
      ber request{ber_alloc_t(LBER_USE_DER)};if(!request.value)fail("gpo_preflight_required");char format[]="{iio}";
      if(ber_printf(request.value,format,0,1048576,cookie.data(),static_cast<ULONG>(cookie.size()))<0)fail("gpo_preflight_required");
      bytes encoded;if(ber_flatten(request.value,&encoded.value)<0||!encoded.value)fail("gpo_preflight_required");
      wchar_t oid[]=L"1.2.840.113556.1.4.841";LDAPControlW control{oid,*encoded.value,TRUE};LDAPControlW* requested[]{&control,nullptr};
      wchar_t attribute[]=L"gPLink";wchar_t* attributes[]{attribute,nullptr};LDAP_TIMEVAL timeout{5,0};message result;
      good(ldap_search_ext_sW(session_,base_dn.data(),LDAP_SCOPE_SUBTREE,filter.data(),attributes,0,requested,nullptr,&timeout,0,&result.value));
      ULONG server_status{};controls returned;wchar_t** referrals{};
      const auto parsed=ldap_parse_resultW(session_,result.value,&server_status,nullptr,nullptr,&referrals,&returned.value,FALSE);
      struct free_referrals{wchar_t** p;~free_referrals(){if(p)ldap_value_freeW(p);}} referral_lifetime{referrals};
      good(parsed);good(server_status);if(referrals&&referrals[0])fail("gpo_preflight_required");
      // A search reference is never interpreted as an empty naming context.
      if(ldap_first_reference(session_,result.value))fail("gpo_preflight_required");
      LDAPControlW* response{};if(returned.value)for(std::size_t n=0;returned.value[n];++n) {
        if(n>=16)fail("gpo_preflight_required");if(wcscmp(returned.value[n]->ldctl_oid,oid)==0){if(response)fail("gpo_preflight_required");response=returned.value[n];}
      }
      if(!response||response->ldctl_value.bv_len>16384)fail("gpo_preflight_required");
      ber decoded{ber_init(&response->ldctl_value)};if(!decoded.value)fail("gpo_preflight_required");long more{},count{};bytes next;char response_format[]="{iiO}";
      if(ber_scanf(decoded.value,response_format,&more,&count,&next.value)==LBER_ERROR||!next.value||next.value->bv_len>8192||
        (more!=0&&more!=1)||count<0)fail("gpo_preflight_required");
      for(auto entry=ldap_first_entry(session_,result.value);entry;entry=ldap_next_entry(session_,entry)) {
        if(++rows>128)fail("gpo_preflight_required");auto raw_dn=ldap_get_dnW(session_,entry);
        struct release_dn{wchar_t* p;~release_dn(){if(p)ldap_memfreeW(p);}} dn_lifetime{raw_dn};if(!raw_dn||wcslen(raw_dn)>2048)fail("gpo_preflight_required");
        const auto dn=lower(utf8(raw_dn));if(dn!=lower(std::string(context))&&!dn.ends_with(","+lower(std::string(context))))fail("gpo_preflight_required");
        const auto value=text(entry,attribute);total_bytes+=value.size();if(total_bytes>8*1024*1024)fail("gpo_preflight_required");
        const auto match=gpo::matching_gpo_link(value,source);if(match&&!found.emplace(dn,*match).second)fail("gpo_preflight_required");
      }
      if(!more)return found;
      const std::string next_cookie(next.value->bv_val,next.value->bv_len);if(next_cookie.empty()||next_cookie==cookie)fail("gpo_preflight_required");cookie=next_cookie;
    }
    fail("gpo_preflight_required");
  }
};
json::array without_own(json::array links,std::string_view id) {
  links.erase(std::remove_if(links.begin(),links.end(),[&](const auto& v){return v.template as<json::object>().at("guid").template as<std::string>()==id;}),links.end());
  for(auto& v:links)v.as<json::object>().erase("order");return links;
}

class native_managed final:public gpo::managed_provider {
  const gpo::job& job_;ComPtr<IGPM> gpm_;ComPtr<IGPMDomain> domain_;ComPtr<IGPMGPO> target_;ComPtr<IGPMBackup> source_;
  std::string current_guid_;const gpo::component_descriptor* component_{};
  std::map<std::string,std::pair<std::string,std::string>> read_dcs_;
  void connect() {
    if(gpm_)return;
    // Reuse the isolated exact-role probe; this public probe starts a separate
    // read-only worker and cannot confer write authority.
    if(!gpo::executor_matches(job_,probe_gpo_executor()))fail("gpo_identity_mismatch");
    check(CoCreateInstance(__uuidof(GPM),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&gpm_)));
    bstr domain(job_.text("domain_dns_name")),dc(job_.text("executor_dc_fqdn"));check(gpm_->GetDomain(domain.value,dc.value,0,&domain_));
    if(lower(property([&](BSTR* p){return domain_->get_Domain(p);}))!=job_.text("domain_dns_name")||
      lower(property([&](BSTR* p){return domain_->get_DomainController(p);}))!=job_.text("executor_dc_fqdn"))fail("gpo_identity_mismatch");
    component_=gpo::component(job_);if(!component_)fail("gpo_unsupported_component");
  }
  void open_target() {
    if(current_guid_.empty()){target_.Reset();return;}
    if(gpo::protected_gpo(current_guid_))fail("gpo_unmanaged_target");
    bstr id(current_guid_);target_.Reset();check(domain_->GetGPO(id.value,&target_));same(current_guid_);
  }
  void same(std::string_view id) {
    if(!target_||gpo::protected_gpo(id)||guid(property([&](BSTR* p){return target_->get_ID(p);}))!=id||
      lower(property([&](BSTR* p){return target_->get_DomainName(p);}))!=job_.text("domain_dns_name"))fail("gpo_unmanaged_target");
  }
  std::string marker()const{return "IPMS managed GPO; id="+job_.text("managed_id");}
  void disable() {check(target_->SetUserEnabled(VARIANT_FALSE));check(target_->SetComputerEnabled(VARIANT_FALSE));}
  void identify() {
    bstr name(job_.text("pilot_display_name")),description(marker());check(target_->put_DisplayName(name.value));
    ComPtr<IGPMGPO2> metadata;check(target_.As(&metadata));check(metadata->put_Description(description.value));
  }
  void import() {if(!source_)fail("gpo_artifact_invalid");ComPtr<IGPMResult> result;check(target_->Import(0,source_.Get(),nullptr,nullptr,nullptr,&result));if(!result)fail();check(result->OverallStatus());}
  ComPtr<IGPMSOM> ou(std::string_view dn) {
    bstr path(dn);ComPtr<IGPMSOM> out;check(domain_->GetSOM(path.value,&out));if(kind(out.Get())!=(component_->scope=="domain"?"domain":"ou")||lower(property([&](BSTR* p){return out->get_Path(p);}))!=lower(std::string(dn)))fail("gpo_target_invalid");return out;
  }
  ComPtr<IGPMSOM> write_ou(std::size_t index) {
    const auto& expected=job_.fields.at("expected_state").as<json::object>().at("ous").as<json::array>().at(index).as<json::object>();
    const auto& dn=job_.fields.at("target_ous").as<json::array>().at(index).as<std::string>();
    auto ads=directory_object(job_,dn);
    if(lower(property([&](BSTR* p){return ads->get_Class(p);}))!=(component_->scope=="domain"?"domaindns":"organizationalunit")||object_guid(ads.Get())!=expected.at("guid").as<std::string>()||
      object_usn(ads.Get())!=expected.at("usn").as<std::string>()||lower(object_text(ads.Get(),L"distinguishedName"))!=lower(expected.at("dn").as<std::string>()))fail("gpo_state_changed");
    auto som=ou(dn);VARIANT_BOOL blocked{};check(som->get_GPOInheritanceBlocked(&blocked));
    if((blocked!=VARIANT_FALSE)!=expected.at("blocked").as<bool>()||json::value(som_links(som.Get()))!=expected.at("links"))fail("gpo_state_changed");
    return som;
  }
  std::string security_digest() {
    ComPtr<IDispatch> raw;check(target_->GetSecurityDescriptor(OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&raw));
    ComPtr<IADsSecurityDescriptor> descriptor;check(raw.As(&descriptor));long revision{},control{};
    check(descriptor->get_Revision(&revision));check(descriptor->get_Control(&control));
    VARIANT_BOOL owner_default{},group_default{},dacl_default{};
    check(descriptor->get_OwnerDefaulted(&owner_default));check(descriptor->get_GroupDefaulted(&group_default));check(descriptor->get_DaclDefaulted(&dacl_default));
    ComPtr<IDispatch> raw_acl;check(descriptor->get_DiscretionaryAcl(&raw_acl));
    // A null/missing DACL or an unrepresentable ACE is not approximated with
    // coarse GPMC permission categories. Preserve every ordered typed field.
    if(!raw_acl)fail("gpo_state_changed");ComPtr<IADsAccessControlList> acl;check(raw_acl.As(&acl));long acl_revision{},count{};
    check(acl->get_AclRevision(&acl_revision));check(acl->get_AceCount(&count));if(count<0||count>256)fail("gpo_target_invalid");
    ComPtr<IUnknown> unknown;check(acl->get__NewEnum(&unknown));ComPtr<IEnumVARIANT> enumeration;check(unknown.As(&enumeration));json::array entries;
    for(long index=0;index<count;++index) {
      variant value;ULONG fetched{};if(enumeration->Next(1,&value.value,&fetched)!=S_OK||fetched!=1)fail("gpo_state_changed");
      auto ace=dispatch<IADsAccessControlEntry>(value.value);long mask{},type{},flags{},object_flags{};
      check(ace->get_AccessMask(&mask));check(ace->get_AceType(&type));check(ace->get_AceFlags(&flags));check(ace->get_Flags(&object_flags));
      // Callback/resource/conditional ACE payloads are not represented by
      // IADsAccessControlEntry and must never silently disappear from a hash.
      if(type!=ACCESS_ALLOWED_ACE_TYPE&&type!=ACCESS_DENIED_ACE_TYPE&&type!=ACCESS_ALLOWED_OBJECT_ACE_TYPE&&type!=ACCESS_DENIED_OBJECT_ACE_TYPE)fail("gpo_state_changed");
      entries.push_back(json::object{{"mask",mask},{"type",type},{"flags",flags},{"object_flags",object_flags},
        {"object_type",property([&](BSTR* p){return ace->get_ObjectType(p);})},
        {"inherited_object_type",property([&](BSTR* p){return ace->get_InheritedObjectType(p);})},
        {"trustee",property([&](BSTR* p){return ace->get_Trustee(p);})}});
    }
    variant extra;ULONG fetched{};if(enumeration->Next(1,&extra.value,&fetched)!=S_FALSE||fetched)fail("gpo_state_changed");
    const auto document=json::serialize(json::object{{"revision",revision},{"control",control},{"acl_revision",acl_revision},
      {"owner",property([&](BSTR* p){return descriptor->get_Owner(p);})},{"group",property([&](BSTR* p){return descriptor->get_Group(p);})},
      {"owner_defaulted",owner_default!=VARIANT_FALSE},{"group_defaulted",group_default!=VARIANT_FALSE},{"dacl_defaulted",dacl_default!=VARIANT_FALSE},{"dacl",std::move(entries)}});
    if(document.size()>262144)fail("gpo_target_invalid");return gpo::sha256(document);
  }
  json::array all_links() {
    try {
      const auto inventory=forest_domains(job_);json::array out;std::map<std::string,std::uint32_t> complete;
      const auto source="cn={"+(target_?current_guid_:job_.text("managed_id"))+"},cn=policies,cn=system,"+domain_dn(job_.text("domain_dns_name"));
      ComPtr<IGPMSearchCriteria> criteria;
      if(target_) {check(gpm_->CreateSearchCriteria(&criteria));VARIANT query{};query.vt=VT_DISPATCH;query.pdispVal=target_.Get();check(criteria->Add(somLinks,opContains,query));}
      const auto append=[&](IGPMSOMCollection* collection){for(const auto& som:items<IGPMSOM>(collection,128))for(const auto& v:som_links(som.Get())) {
        const auto& link=v.as<json::object>();if(link.at("guid").as<std::string>()==current_guid_&&link.at("domain").as<std::string>()==job_.text("domain_dns_name"))out.push_back(v);
        if(out.size()>128)fail("gpo_preflight_required");
      }};
      const auto merge=[&](const auto& locations){for(const auto& [dn,flags]:locations)if(!complete.emplace(dn,flags).second||complete.size()>128)fail("gpo_preflight_required");};
      for(const auto& item:inventory) {
        auto cached=read_dcs_.find(item.dns_name);
        if(cached==read_dcs_.end())cached=read_dcs_.emplace(item.dns_name,std::make_pair(item.guid,discover_dc(job_,item))).first;
        if(cached->second.first!=item.guid)fail("gpo_preflight_required");const auto& controller=cached->second.second;
        link_visibility_reader reader(job_,item,controller);const auto locations=reader.links(reader.naming_context,source);
        if(target_) {
          // This domain object is scoped to read-only census code. The mutation
          // provider keeps its original exact approved domain/DC object.
          ComPtr<IGPMDomain> read_domain;bstr dns(item.dns_name),dc(controller);check(gpm_->GetDomain(dns.value,dc.value,0,&read_domain));
          if(lower(property([&](BSTR* p){return read_domain->get_Domain(p);}))!=item.dns_name||
            lower(property([&](BSTR* p){return read_domain->get_DomainController(p);}))!=controller)fail("gpo_preflight_required");
          ComPtr<IGPMSOMCollection> matches;check(read_domain->SearchSOMs(criteria.Get(),&matches));append(matches.Get());merge(locations);
        }
        if(item.primary) {
          const auto sites_found=reader.links(reader.configuration_context,source);
          if(target_) {
            ComPtr<IGPMSitesContainer> sites;bstr forest(job_.text("forest_dns_name")),dns(item.dns_name),dc(controller);
            check(gpm_->GetSitesContainer(forest.value,dns.value,dc.value,0,&sites));ComPtr<IGPMSOMCollection> matches;
            check(sites->SearchSites(criteria.Get(),&matches));append(matches.Get());merge(sites_found);
          }
        }
      }
      if(forest_domains(job_)!=inventory)fail("gpo_preflight_required");
      // Initial imports perform the same capability/completeness query using
      // the immutable managed UUID as a read-only probe before any GPO exists.
      if(target_)gpo::verify_forest_link_census(out,complete);
      std::sort(out.begin(),out.end(),[](const auto& a,const auto& b){const auto& x=a.template as<json::object>();const auto& y=b.template as<json::object>();
        return std::tuple(x.at("kind").template as<std::string>(),lower(x.at("dn").template as<std::string>()),x.at("order").template as<std::int64_t>())<
               std::tuple(y.at("kind").template as<std::string>(),lower(y.at("dn").template as<std::string>()),y.at("order").template as<std::int64_t>());});return out;
    }catch(...){fail("gpo_preflight_required");}
  }
  bool name_available() {
    ComPtr<IGPMSearchCriteria> criteria;check(gpm_->CreateSearchCriteria(&criteria));bstr name(job_.text("pilot_display_name"));VARIANT query{};query.vt=VT_BSTR;query.bstrVal=name.value;check(criteria->Add(gpoDisplayName,opEquals,query));
    ComPtr<IGPMGPOCollection> collection;check(domain_->SearchGPOs(criteria.Get(),&collection));const auto found=items<IGPMGPO>(collection.Get(),128);
    return std::all_of(found.begin(),found.end(),[&](const auto& g){return guid(property([&](BSTR* p){return g->get_ID(p);}))==current_guid_;});
  }
 public:
  explicit native_managed(const gpo::job& j):job_(j),current_guid_(j.text("gpo_guid")){}
  json::object inspect() override {
    connect();open_target();json::array ous;
    for(const auto& item:job_.fields.at("target_ous").as<json::array>()) {
      const auto& dn=item.as<std::string>();auto ads=directory_object(job_,dn);
      if(lower(property([&](BSTR* p){return ads->get_Class(p);}))!=(component_->scope=="domain"?"domaindns":"organizationalunit"))fail("gpo_target_invalid");
      const auto actual=object_text(ads.Get(),L"distinguishedName");if(lower(actual)!=lower(dn))fail("gpo_target_invalid");
      auto som=ou(actual);VARIANT_BOOL blocked{};check(som->get_GPOInheritanceBlocked(&blocked));
      ous.push_back(json::object{{"dn",actual},{"guid",object_guid(ads.Get())},{"usn",object_usn(ads.Get())},{"blocked",blocked!=VARIANT_FALSE},
        {"links",som_links(som.Get())},{"inherited_links",component_->scope=="domain"?json::array{}:som_links(som.Get(),true)}});
    }
    auto links=all_links();json::value g;
    if(target_) {
      VARIANT_BOOL computer{},user{},consistent{};long cds{},css{},uds{},uss{};
      check(target_->IsComputerEnabled(&computer));check(target_->IsUserEnabled(&user));check(target_->IsACLConsistent(&consistent));
      check(target_->get_ComputerDSVersionNumber(&cds));check(target_->get_ComputerSysvolVersionNumber(&css));check(target_->get_UserDSVersionNumber(&uds));check(target_->get_UserSysvolVersionNumber(&uss));
      if(consistent!=VARIANT_TRUE||cds!=css||uds!=uss)fail("gpo_state_changed");
      ComPtr<IGPMGPO2> metadata;check(target_.As(&metadata));ComPtr<IGPMWMIFilter> filter;check(target_->GetWMIFilter(&filter));
      g=json::object{{"guid",current_guid_},{"name",property([&](BSTR* p){return target_->get_DisplayName(p);})},
        {"description",property([&](BSTR* p){return metadata->get_Description(p);})},{"computer_enabled",computer!=VARIANT_FALSE},{"user_enabled",user!=VARIANT_FALSE},
        {"computer_ds",cds},{"computer_sysvol",css},{"user_ds",uds},{"user_sysvol",uss},{"security_digest",security_digest()},
        {"wmi_filter",filter?property([&](BSTR* p){return filter->get_Path(p);}):""},{"links",std::move(links)}};
    }
    json::object state{{"schema",1},{"gpo",std::move(g)},{"ous",std::move(ous)},{"name_available",name_available()}};
    if(!gpo::valid_snapshot(state))fail("gpo_target_invalid");
    // Leave space for both before/after state in a protected 64 KiB journal.
    if(json::serialize(state).size()>16384)fail("gpo_target_invalid");return state;
  }
  void prepare() override {
    connect();const auto path=expand_gpo_artifact(job_);ComPtr<IGPMBackupDir> backups;bstr directory(path.wstring()),id(component_->backup_id);
    check(gpm_->GetBackupDir(directory.value,&backups));check(backups->GetBackup(id.value,&source_));
    if(guid(property([&](BSTR* p){return source_->get_ID(p);}))!=guid(std::string(component_->backup_id))||
      guid(property([&](BSTR* p){return source_->get_GPOID(p);}))!=guid(std::string(component_->source_gpo_id)))fail("gpo_source_mismatch");
  }
  std::string create() override {
    if(!current_guid_.empty())fail("gpo_unmanaged_target");check(domain_->CreateGPO(&target_));current_guid_=guid(property([&](BSTR* p){return target_->get_ID(p);}));same(current_guid_);return current_guid_;
  }
  void initialize(std::string_view id) override {same(id);disable();identify();import();disable();}
  void adopt(std::string_view id) override {same(id);identify();}
  std::pair<std::string,std::string> backup(std::string_view id) override {
    same(id);
    try {
      const auto root=gpo_storage_directory();ensure_gpo_directory(root);const auto job=root/wide(job_.text("job_id"));ensure_gpo_directory(job);
      const auto path=job/L"recovery-backup";
      if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES)fail("gpo_backup_failed");ensure_gpo_directory(path);
      ComPtr<IGPMResult> result;bstr directory(path.wstring()),comment("IPMS managed GPO recovery; job="+job_.text("job_id"));
      check(target_->Backup(directory.value,comment.value,nullptr,nullptr,&result));if(!result)fail("gpo_backup_failed");check(result->OverallStatus());
      variant returned;check(result->get_Result(&returned.value));auto backup=dispatch<IGPMBackup>(returned.value);
      const auto backup_id=guid(property([&](BSTR* p){return backup->get_ID(p);}));
      if(guid(property([&](BSTR* p){return backup->get_GPOID(p);}))!=id)fail("gpo_backup_failed");
      json::array files;std::uint64_t total{};std::size_t entries{};
      for(const auto& entry:std::filesystem::recursive_directory_iterator(path)) {
        if(++entries>1024)fail("gpo_backup_failed");const auto attrs=GetFileAttributesW(entry.path().c_str());
        if(attrs==INVALID_FILE_ATTRIBUTES||(attrs&FILE_ATTRIBUTE_REPARSE_POINT))fail("gpo_backup_failed");
        if(attrs&FILE_ATTRIBUTE_DIRECTORY){ensure_gpo_directory(entry.path());continue;}
        const auto bytes=read_protected_gpo_file(entry.path(),16*1024*1024);total+=bytes.size();if(total>64*1024*1024)fail("gpo_backup_failed");
        files.push_back(json::object{{"path",utf8(entry.path().lexically_relative(path).generic_wstring())},{"bytes",bytes.size()},{"sha256",gpo::sha256(bytes)}});
      }
      if(files.empty())fail("gpo_backup_failed");std::sort(files.begin(),files.end(),[](const auto& a,const auto& b){return a.template as<json::object>().at("path").template as<std::string>()<b.template as<json::object>().at("path").template as<std::string>();});
      const auto document=json::serialize(json::object{{"schema",1},{"job_id",job_.text("job_id")},{"input_digest",job_.text("input_digest")},
        {"gpo_guid",id},{"backup_id",backup_id},{"files",std::move(files)}});
      const auto manifest=job/L"recovery-manifest.json";write_protected_gpo_file(manifest,document,false);
      if(read_protected_gpo_file(manifest,65536)!=document)fail("gpo_backup_failed");return {backup_id,gpo::sha256(document)};
    }catch(...){fail("gpo_backup_failed");}
  }
  void link(std::string_view id) override {
    same(id);VARIANT_BOOL computer{},user{};check(target_->IsComputerEnabled(&computer));check(target_->IsUserEnabled(&user));
    if(computer!=VARIANT_FALSE||user!=VARIANT_FALSE)fail("gpo_requires_disabled");
    const auto& targets=job_.fields.at("target_ous").as<json::array>();const auto& orders=job_.fields.at("link_orders").as<json::array>();
    for(std::size_t n=0;n<targets.size();++n) {
      auto som=write_ou(n);const auto before=som_links(som.Get());ComPtr<IGPMGPOLinksCollection> collection;check(som->GetGPOLinks(&collection));
      ComPtr<IGPMGPOLink> own;for(const auto& candidate:items<IGPMGPOLink>(collection.Get(),128))if(guid(property([&](BSTR* p){return candidate->get_GPOID(p);}))==id) {
        if(own)fail("gpo_link_conflict");own=candidate;
      }
      const auto position=static_cast<long>(orders[n].as<std::int64_t>());const auto remaining=before.size()-(own?1:0);
      if(position<1||static_cast<std::size_t>(position)>remaining+1)fail("gpo_link_conflict");
      if(own) {
        VARIANT_BOOL enabled{},enforced{};long order{};check(own->get_Enabled(&enabled));check(own->get_Enforced(&enforced));check(own->get_SOMLinkOrder(&order));
        if(enforced!=VARIANT_FALSE)fail("gpo_link_conflict");
        if(enabled!=VARIANT_FALSE)check(own->put_Enabled(VARIANT_FALSE));
        if(order==position)continue;
        // No GPMC order setter exists. Only our already disabled link is
        // replaced, while both halves are disabled; unrelated links stay put.
        check(own->Delete());own.Reset();
      }
      check(som->CreateGPOLink(position,target_.Get(),&own));check(own->put_Enabled(VARIANT_FALSE));check(own->put_Enforced(VARIANT_FALSE));
      const auto after=som_links(som.Get());if(without_own(before,id)!=without_own(after,id))fail("gpo_state_changed");
      const auto created=link_state(own.Get());if(created.at("order").as<std::int64_t>()!=position||created.at("enabled").as<bool>()||created.at("enforced").as<bool>())fail("gpo_verification_failed");
    }
  }
  void activate(std::string_view id) override {
    same(id);const bool machine=component_->scope=="machine"||component_->scope=="domain",user=component_->scope=="user";
    if(!machine&&!user)fail("gpo_unsupported_component");
    import();identify();
    check(target_->SetComputerEnabled(machine?VARIANT_TRUE:VARIANT_FALSE));check(target_->SetUserEnabled(user?VARIANT_TRUE:VARIANT_FALSE));
    const auto& targets=job_.fields.at("target_ous").as<json::array>();
    for(std::size_t index=0;index<targets.size();++index) {
      auto som=write_ou(index);ComPtr<IGPMGPOLinksCollection> collection;check(som->GetGPOLinks(&collection));bool found=false;
      for(const auto& link:items<IGPMGPOLink>(collection.Get(),128))if(guid(property([&](BSTR* p){return link->get_GPOID(p);}))==id) {
        VARIANT_BOOL enforced{};check(link->get_Enforced(&enforced));if(found||enforced!=VARIANT_FALSE)fail("gpo_link_conflict");
        found=true;check(link->put_Enabled(VARIANT_TRUE));
      }
      if(!found)fail("gpo_link_conflict");
    }
  }
  void deactivate(std::string_view id) override {same(id);disable();}
};
}
std::unique_ptr<gpo::managed_provider> make_managed_gpo_provider(const gpo::job& job) {return std::make_unique<native_managed>(job);}
}  // namespace ipms::agent::windows
