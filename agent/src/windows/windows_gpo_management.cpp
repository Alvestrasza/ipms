// File Name: windows_gpo_management.cpp
// Version: v0.2.0 | Created: 2026-09-14 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Fixed isolated native GPMC import into newly created disabled, unlinked pilot GPOs.
#include "ipms/agent/windows_gpo_management.hpp"
#include <windows.h>
#include <dsrole.h>
#include <gpmgmt.h>
#include <tlhelp32.h>
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <iostream>
#include <memory>

namespace ipms::agent::windows {
namespace {
namespace json=gpo::json;
using Microsoft::WRL::ComPtr;
struct closer { void operator()(void* p) const { if(p&&p!=INVALID_HANDLE_VALUE) CloseHandle(p); } };
using handle=std::unique_ptr<void,closer>;
[[noreturn]] void fail(std::string code="gpo_provider_failed") { throw gpo::operation_error(std::move(code)); }
void check(HRESULT hr) { if(FAILED(hr)) fail(hr==E_ACCESSDENIED||hr==HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)?"gpo_permission_denied":
  hr==REGDB_E_CLASSNOTREG?"gpmc_unavailable":"gpo_provider_failed"); }
std::wstring wide(std::string_view s) {
  if(s.empty()) return {}; const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
  if(!n) fail(); std::wstring out(n,L'\0');
  if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n)!=n) fail(); return out;
}
std::string utf8(std::wstring_view s) {
  if(s.empty()) return {}; const auto n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
  if(!n) fail(); std::string out(n,'\0');
  if(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr)!=n) fail(); return out;
}
std::string lower(std::string s) { for(auto& c:s) if(c>='A'&&c<='Z') c=static_cast<char>(c-'A'+'a'); return s; }
std::string guid(std::string s) {
  if(s.size()==38&&s.front()=='{'&&s.back()=='}') s=s.substr(1,36);
  s=lower(std::move(s)); if(!gpo::valid_uuid(s)) fail("gpo_domain_identity_unavailable"); return s;
}
struct bstr {
  BSTR value{};
  explicit bstr(std::wstring_view s):value(SysAllocStringLen(s.data(),static_cast<UINT>(s.size()))) { if(!value) fail(); }
  explicit bstr(std::string_view s):bstr(wide(s)) {}
  ~bstr() { SysFreeString(value); }
  bstr(const bstr&)=delete;
};
template<class F> std::string string_property(F getter) {
  BSTR raw{}; const auto hr=getter(&raw);
  struct release { BSTR p; ~release(){SysFreeString(p);} } lifetime{raw};
  check(hr); return raw?utf8({raw,SysStringLen(raw)}):std::string{};
}
struct com_scope {
  com_scope() { check(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED));
    check(CoInitializeSecurity(nullptr,-1,nullptr,nullptr,RPC_C_AUTHN_LEVEL_PKT_PRIVACY,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_DISABLE_AAA,nullptr)); }
  ~com_scope(){CoUninitialize();}
};
ComPtr<IGPM> gpm() {
  ComPtr<IGPM> value; check(CoCreateInstance(__uuidof(GPM),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&value))); return value;
}
json::object executor_identity() {
  json::object out{{"schema",1},{"domain_dns_name",""},{"domain_guid",""},{"forest_dns_name",""},{"dc_fqdn",""},
      {"role","unknown"},{"gpmc_available",false},{"result_code","domain_identity_unavailable"}};
  PBYTE raw{};
  const auto status=DsRoleGetPrimaryDomainInformation(nullptr,DsRolePrimaryDomainInfoBasic,&raw);
  struct release { PBYTE p; ~release(){if(p)DsRoleFreeMemory(p);} } lifetime{raw};
  if(status!=ERROR_SUCCESS||!raw) return out;
  const auto& info=*reinterpret_cast<DSROLE_PRIMARY_DOMAIN_INFO_BASIC*>(raw);
  if(info.DomainNameDns) out["domain_dns_name"]=lower(utf8(info.DomainNameDns));
  if(info.DomainForestName) out["forest_dns_name"]=lower(utf8(info.DomainForestName));
  if(info.Flags&DSROLE_PRIMARY_DOMAIN_GUID_PRESENT) { std::array<wchar_t,40> value{};
    if(StringFromGUID2(info.DomainGuid,value.data(),static_cast<int>(value.size()))) out["domain_guid"]=guid(utf8(value.data())); }
  std::array<wchar_t,256> name{}; DWORD length=static_cast<DWORD>(name.size());
  if(GetComputerNameExW(ComputerNameDnsFullyQualified,name.data(),&length)) out["dc_fqdn"]=lower(utf8({name.data(),length}));
  const bool dc=info.MachineRole==DsRole_RolePrimaryDomainController||info.MachineRole==DsRole_RoleBackupDomainController;
  if(!dc) { out["role"]="not-domain-controller";out["result_code"]="not_writable_domain_controller";return out; }
  if(info.Flags&DSROLE_PRIMARY_DS_READONLY) { out["role"]="read-only-domain-controller";out["result_code"]="not_writable_domain_controller";return out; }
  if(!(info.Flags&DSROLE_PRIMARY_DS_RUNNING)||out.at("domain_guid").as<std::string>().empty()||
      out.at("dc_fqdn").as<std::string>().empty()) return out;
  out["role"]="writable-domain-controller";
  try { auto provider=gpm(); out["gpmc_available"]=true;out["result_code"]="ready_for_approval"; }
  catch(...) {out["result_code"]="gpmc_unavailable";}
  return out;
}

class native_provider final:public gpo::pilot_provider {
  const gpo::job& job_;
  const gpo::component_descriptor* component_{};
  ComPtr<IGPM> gpm_;
  ComPtr<IGPMDomain> domain_;
  ComPtr<IGPMBackup> backup_;
  ComPtr<IGPMGPO> created_;
  void same(std::string_view id) {
    if(!created_||!gpo::valid_uuid(id)||gpo::protected_gpo(id)||
        guid(string_property([&](BSTR* v){return created_->get_ID(v);}))!=id||
        lower(string_property([&](BSTR* v){return created_->get_DomainName(v);}))!=job_.text("domain_dns_name")) fail("gpo_verification_failed");
  }
 public:
  explicit native_provider(const gpo::job& job):job_(job) {}
  void preflight() override {
    const auto identity=executor_identity();
    if(!gpo::executor_matches(job_,identity)) fail(identity.at("gpmc_available").as<bool>()?"gpo_identity_mismatch":
        identity.at("role").as<std::string>()=="writable-domain-controller"?"gpmc_unavailable":"gpo_not_writable_dc");
    component_=gpo::component(job_); if(!component_) fail("gpo_unsupported_component");
    const auto directory=expand_gpo_artifact(job_); gpm_=gpm();
    bstr domain(job_.text("domain_dns_name")),dc(job_.text("executor_dc_fqdn"));
    check(gpm_->GetDomain(domain.value,dc.value,0,&domain_));
    if(lower(string_property([&](BSTR* v){return domain_->get_Domain(v);}))!=job_.text("domain_dns_name")||
        lower(string_property([&](BSTR* v){return domain_->get_DomainController(v);}))!=job_.text("executor_dc_fqdn")) fail("gpo_identity_mismatch");
    ComPtr<IGPMSearchCriteria> search;check(gpm_->CreateSearchCriteria(&search));
    bstr display(job_.text("pilot_display_name")); VARIANT value{};value.vt=VT_BSTR;value.bstrVal=display.value;
    check(search->Add(gpoDisplayName,opEquals,value));
    ComPtr<IGPMGPOCollection> matches;check(domain_->SearchGPOs(search.Get(),&matches));
    long count{};check(matches->get_Count(&count));if(count!=0)fail("gpo_name_collision");
    ComPtr<IGPMBackupDir> backups;bstr local(directory.wstring());check(gpm_->GetBackupDir(local.value,&backups));
    bstr backup_id(component_->backup_id);check(backups->GetBackup(backup_id.value,&backup_));
    if(guid(string_property([&](BSTR* v){return backup_->get_ID(v);}))!=guid(std::string(component_->backup_id))||
        guid(string_property([&](BSTR* v){return backup_->get_GPOID(v);}))!=guid(std::string(component_->source_gpo_id))) fail("gpo_source_mismatch");
  }
  std::string create() override {
    check(domain_->CreateGPO(&created_));
    return guid(string_property([&](BSTR* v){return created_->get_ID(v);}));
  }
  void disable(std::string_view id) override { same(id);check(created_->SetUserEnabled(VARIANT_FALSE));check(created_->SetComputerEnabled(VARIANT_FALSE)); }
  void identify(std::string_view id) override {
    same(id);bstr display(job_.text("pilot_display_name"));check(created_->put_DisplayName(display.value));
    ComPtr<IGPMGPO2> metadata;check(created_.As(&metadata));
    bstr description("IPMS disabled, unlinked pilot; job="+job_.text("job_id")+"; digest="+job_.text("input_digest"));
    check(metadata->put_Description(description.value));
  }
  void import_settings(std::string_view id) override {
    same(id);ComPtr<IGPMResult> outcome;
    // All imported bytes are from the compiled Microsoft package census. Flag0
    // imports settings without copying the original lab-domain GPO DACL.
    check(created_->Import(0,backup_.Get(),nullptr,nullptr,nullptr,&outcome));
    if(!outcome)fail();check(outcome->OverallStatus());
  }
  json::object verify(std::string_view id) override {
    same(id);VARIANT_BOOL user{},computer{},consistent{};
    check(created_->IsUserEnabled(&user));check(created_->IsComputerEnabled(&computer));check(created_->IsACLConsistent(&consistent));
    if(user!=VARIANT_FALSE||computer!=VARIANT_FALSE||consistent!=VARIANT_TRUE)fail("gpo_verification_failed");
    if(string_property([&](BSTR* v){return created_->get_DisplayName(v);})!=job_.text("pilot_display_name")) fail("gpo_verification_failed");
    ComPtr<IGPMWMIFilter> filter;check(created_->GetWMIFilter(&filter));if(filter)fail("gpo_verification_failed");
    long user_ds{},user_sysvol{},computer_ds{},computer_sysvol{};
    check(created_->get_UserDSVersionNumber(&user_ds));check(created_->get_UserSysvolVersionNumber(&user_sysvol));
    check(created_->get_ComputerDSVersionNumber(&computer_ds));check(created_->get_ComputerSysvolVersionNumber(&computer_sysvol));
    if(user_ds!=user_sysvol||computer_ds!=computer_sysvol)fail("gpo_verification_failed");
    ComPtr<IGPMSearchCriteria> search;check(gpm_->CreateSearchCriteria(&search));
    VARIANT value{};value.vt=VT_DISPATCH;value.pdispVal=created_.Get();check(search->Add(somLinks,opContains,value));
    ComPtr<IGPMSOMCollection> links;check(domain_->SearchSOMs(search.Get(),&links));long count{};check(links->get_Count(&count));
    if(count!=0)fail("gpo_verification_failed");
    ComPtr<IGPMSitesContainer> sites;bstr forest(job_.text("forest_dns_name")),domain(job_.text("domain_dns_name")),dc(job_.text("executor_dc_fqdn"));
    check(gpm_->GetSitesContainer(forest.value,domain.value,dc.value,0,&sites));
    links.Reset();check(sites->SearchSites(search.Get(),&links));check(links->get_Count(&count));if(count!=0)fail("gpo_verification_failed");
    return {{"computer_enabled",false},{"user_enabled",false},{"unlinked",true},{"domain_dns_name",job_.text("domain_dns_name")},
      {"domain_guid",job_.text("domain_guid")},{"dc_fqdn",job_.text("executor_dc_fqdn")}};
  }
};

json::object worker_call(std::string_view action,std::chrono::seconds timeout,const std::function<bool()>& cancelled) {
  std::array<wchar_t,32768> executable{};const auto length=GetModuleFileNameW(nullptr,executable.data(),static_cast<DWORD>(executable.size()));
  if(!length||length>=executable.size())fail("gpo_worker_failed");
  const std::wstring path(executable.data(),length);if(path.find(L'"')!=path.npos)fail("gpo_worker_failed");
  std::wstring command=L"\""+path+L"\" --gpo-worker";
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
  HANDLE ir{},iw{},orr{},ow{};
  if(!CreatePipe(&ir,&iw,&sa,4096))fail("gpo_worker_failed");handle input_reader(ir),input_writer(iw);
  if(!CreatePipe(&orr,&ow,&sa,16384))fail("gpo_worker_failed");handle output_reader(orr),output_writer(ow);
  if(!SetHandleInformation(iw,HANDLE_FLAG_INHERIT,0)||!SetHandleInformation(orr,HANDLE_FLAG_INHERIT,0))fail("gpo_worker_failed");
  handle null(CreateFileW(L"NUL",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,nullptr));
  handle group(CreateJobObjectW(nullptr,nullptr));if(null.get()==INVALID_HANDLE_VALUE||!group)fail("gpo_worker_failed");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY;
  limits.BasicLimitInformation.ActiveProcessLimit=1;limits.ProcessMemoryLimit=256*1024*1024;
  if(!SetInformationJobObject(group.get(),JobObjectExtendedLimitInformation,&limits,sizeof(limits)))fail("gpo_worker_failed");
  SIZE_T bytes{};InitializeProcThreadAttributeList(nullptr,1,0,&bytes);std::vector<std::uint8_t> attributes(bytes);
  auto* list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
  if(!InitializeProcThreadAttributeList(list,1,0,&bytes))fail("gpo_worker_failed");
  struct release { LPPROC_THREAD_ATTRIBUTE_LIST p;~release(){DeleteProcThreadAttributeList(p);} } lifetime{list};
  std::array<HANDLE,3> inherited{ir,ow,null.get()};
  if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited.data(),sizeof(inherited),nullptr,nullptr))fail("gpo_worker_failed");
  STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput=ir;startup.StartupInfo.hStdOutput=ow;startup.StartupInfo.hStdError=null.get();startup.lpAttributeList=list;
  PROCESS_INFORMATION raw{};
  if(!CreateProcessW(path.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT,
      nullptr,nullptr,&startup.StartupInfo,&raw))fail("gpo_worker_failed");
  handle process(raw.hProcess),thread(raw.hThread);
  if(!AssignProcessToJobObject(group.get(),process.get())){TerminateProcess(process.get(),1);fail("gpo_worker_failed");}
  struct terminate_on_error {HANDLE group;HANDLE process;~terminate_on_error(){TerminateJobObject(group,1);WaitForSingleObject(process,2000);} } cleanup{group.get(),process.get()};
  const auto input=json::serialize(json::object{{"action",action}});DWORD written{};
  if(!WriteFile(iw,input.data(),static_cast<DWORD>(input.size()),&written,nullptr)||written!=input.size())fail("gpo_worker_failed");
  input_writer.reset();if(ResumeThread(thread.get())==static_cast<DWORD>(-1))fail("gpo_worker_failed");input_reader.reset();output_writer.reset();
  const auto deadline=std::chrono::steady_clock::now()+timeout;std::string output;
  for(;;) {
    if((cancelled&&cancelled())||std::chrono::steady_clock::now()>=deadline)fail("gpo_worker_timeout");
    DWORD available{};const auto ok=PeekNamedPipe(output_reader.get(),nullptr,0,nullptr,&available,nullptr);
    if(!ok&&GetLastError()!=ERROR_BROKEN_PIPE)fail("gpo_worker_failed");
    if(available) {
      std::array<char,8192> buffer{};DWORD read{};
      if(!ReadFile(output_reader.get(),buffer.data(),(std::min)(available,static_cast<DWORD>(buffer.size())),&read,nullptr)||!read)fail("gpo_worker_failed");
      if(output.size()+read>65536)fail("gpo_worker_failed");output.append(buffer.data(),read);
    } else if(WaitForSingleObject(process.get(),0)==WAIT_OBJECT_0) {
      DWORD code{};if(!GetExitCodeProcess(process.get(),&code)||code)fail("gpo_worker_failed");
      return json::parse(output).as<json::object>();
    }
    WaitForSingleObject(process.get(),10);
  }
}
}  // namespace

json::object probe_gpo_executor(const std::function<bool()>& cancelled) {
  try {return worker_call("inspect",std::chrono::seconds(20),cancelled);}
  catch(...) {return {{"schema",1},{"domain_dns_name",""},{"domain_guid",""},{"forest_dns_name",""},{"dc_fqdn",""},
    {"role","unknown"},{"gpmc_available",false},{"result_code","executor_probe_failed"}};}
}
json::object invoke_gpo_pilot_worker(const std::function<bool()>& cancelled) {
  try {
    const auto out=worker_call("execute",std::chrono::seconds(120),cancelled);
    if(!gpo::valid_result(out))fail("gpo_worker_failed");return out;
  } catch(const std::exception& error) {
    auto recorded=load_gpo_journal();if(!recorded)throw;
    if(recorded->state==gpo::phase::terminal||recorded->state==gpo::phase::reconciliation) return recorded->result.as<json::object>();
    auto receipt=gpo::result("requires_reconciliation",std::string_view(error.what())=="gpo_worker_timeout"?"gpo_worker_timeout":"gpo_worker_failed",recorded->gpo_guid);
    recorded->state=gpo::phase::reconciliation;recorded->result=receipt;save_gpo_journal(*recorded);
    return receipt;
  }
}
json::object invoke_gpo_inspection_worker(const std::function<bool()>& cancelled) {
  try {const auto out=worker_call("inspect_managed",std::chrono::seconds(120),cancelled);
    if(!gpo::valid_result(out))fail("gpo_worker_failed");return out;
  } catch(...) {
    auto record=load_gpo_journal();if(!record||!gpo::inspection(record->assignment))throw;
    if(record->state==gpo::phase::terminal)return record->result.as<json::object>();
    if(record->state!=gpo::phase::prepared)throw;
    record->state=gpo::phase::terminal;record->result=gpo::result("failed","gpo_worker_failed");save_gpo_journal(*record);
    return record->result.as<json::object>();
  }
}
bool gpo_worker_quiescent() {
  // current.lock is held by the caller throughout this census and the read.
  // Unlike a newly introduced worker.lock, this also detects pre-upgrade
  // workers which did not participate in the new exclusion protocol.
  const auto manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!manager)return false;
  struct service_close {SC_HANDLE h;~service_close(){if(h)CloseServiceHandle(h);}} manager_lifetime{manager};
  const auto service=OpenServiceW(manager,L"IPMS Agent",SERVICE_QUERY_STATUS);if(!service)return false;service_close service_lifetime{service};
  SERVICE_STATUS_PROCESS status{};DWORD bytes{};
  if(!QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<LPBYTE>(&status),sizeof(status),&bytes)||
      status.dwCurrentState!=SERVICE_RUNNING||status.dwProcessId!=GetCurrentProcessId())return false;
  std::array<wchar_t,32768> executable{};const auto size=GetModuleFileNameW(nullptr,executable.data(),static_cast<DWORD>(executable.size()));
  if(!size||size>=executable.size()||_wcsicmp(std::filesystem::path(executable.data()).filename().c_str(),L"ipms-agent.exe")!=0)return false;
  handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if(snapshot.get()==INVALID_HANDLE_VALUE)return false;
  PROCESSENTRY32W item{};item.dwSize=sizeof(item);if(!Process32FirstW(snapshot.get(),&item))return false;
  std::size_t count{},own{};
  do {
    if(++count>65536)return false;
    if(_wcsicmp(item.szExeFile,L"ipms-agent.exe")==0) {if(item.th32ProcessID!=GetCurrentProcessId())return false;++own;}
  }while(Process32NextW(snapshot.get(),&item));
  return GetLastError()==ERROR_NO_MORE_FILES&&own==1;
}
json::object invoke_gpo_reconciliation_worker(const std::function<bool()>& cancelled) {
  const auto record=load_gpo_journal();if(!record||record->state!=gpo::phase::reconciliation)fail("gpo_journal_invalid");
  if(!gpo_worker_quiescent())return gpo::unavailable_observation(record->gpo_guid,"gpo_reconciliation_quiescence_unavailable");
  try {
    auto observed=worker_call("reconcile",std::chrono::seconds(120),cancelled);
    if(!gpo_worker_quiescent())return gpo::unavailable_observation(record->gpo_guid,"gpo_reconciliation_quiescence_unavailable");
    observed["quiescent"]=true;
    if(!gpo::valid_reconciliation_observation(observed))return gpo::unavailable_observation(record->gpo_guid,"gpo_reconciliation_result_invalid",true);
    return observed;
  }catch(const std::exception& error) {
    return gpo::unavailable_observation(record->gpo_guid,std::string_view(error.what())=="gpo_worker_timeout"?
      "gpo_reconciliation_worker_timeout":"gpo_reconciliation_worker_failed",gpo_worker_quiescent());
  }catch(...) {return gpo::unavailable_observation(record->gpo_guid,"gpo_reconciliation_worker_failed",gpo_worker_quiescent());}
}
int run_gpo_worker() {
  try {
    const HANDLE input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE);std::string document;
    for(;;){std::array<char,1024> buffer{};DWORD read{};if(!ReadFile(input,buffer.data(),static_cast<DWORD>(buffer.size()),&read,nullptr)){
      if(GetLastError()==ERROR_BROKEN_PIPE)break;return 1;}if(!read)break;if(document.size()+read>4096)return 1;document.append(buffer.data(),read);}
    const auto request=json::parse(document).as<json::object>();if(request.size()!=1)return 1;
    const auto action=request.at("action").as<std::string>();json::object response;
    com_scope apartment;
    if(action=="inspect")response=executor_identity();
    else if(action=="inspect_managed") {
      auto record=load_gpo_journal();if(!record||!gpo::inspection(record->assignment))return 1;
      auto provider=make_managed_gpo_provider(record->assignment,executor_identity());
      response=gpo::inspect_managed(*record,*provider,save_gpo_journal,[&]{return gpo::unexpired(record->assignment)&&gpo_enrollment_matches(record->device_uri);});
    }
    else if(action=="reconcile") {
      handle exclusive(acquire_gpo_worker_lock());if(!exclusive)return 1;
      auto record=load_gpo_journal();if(!record||record->state!=gpo::phase::reconciliation)return 1;
      const auto challenge=load_gpo_reconciliation_request(*record);
      if(challenge.at("mode").as<std::string>()=="released"||!gpo_enrollment_matches(record->device_uri))return 1;
      response=observe_gpo_reconciliation(*record,executor_identity());
      if(load_gpo_reconciliation_request(*record)!=challenge||!gpo_enrollment_matches(record->device_uri))return 1;
    }
    else if(action=="execute") {
      handle exclusive(acquire_gpo_worker_lock());if(!exclusive)return 1;
      auto record=load_gpo_journal();if(!record)return 1;
      const auto authority=[&]{return gpo::unexpired(record->assignment)&&
        gpo::grant_current(*record,GetTickCount64())&&gpo_enrollment_matches(record->device_uri)&&
        (record->assignment.number("schema")==1||
          gpo::portal_approval_current(record->portal_approval,record->assignment,record->device_uri));};
      const auto consume=[&]{if(record->assignment.number("schema")>=2)consume_gpo_portal_approval(*record);
        else consume_gpo_local_approval(record->assignment,record->device_uri);};
      if(record->assignment.number("schema")>=3) {
        auto provider=make_managed_gpo_provider(record->assignment,executor_identity());
        response=gpo::execute_managed(*record,*provider,save_gpo_journal,authority,consume);
      }else {
        native_provider provider(record->assignment);
        response=gpo::execute_pilot(*record,provider,save_gpo_journal,authority,consume);
      }
    }else return 1;
    const auto text=json::serialize(response);DWORD written{};
    if(!WriteFile(output,text.data(),static_cast<DWORD>(text.size()),&written,nullptr)||written!=text.size())return 1;
    return 0;
  }catch(...){return 1;}
}
}  // namespace ipms::agent::windows
