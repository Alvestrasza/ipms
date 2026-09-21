// File Name: windows_hgs_management.cpp
// Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Embedded bounded HGS adapter, protected receipts and isolated cancellable execution.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>
#include "ipms/agent/windows_hgs_management.hpp"
#include "ipms/agent/windows_gpo_management.hpp"
#include "ipms/agent/hgs_adapter_content.hpp"
#include <array>
#include <filesystem>
#include <memory>
#include <vector>

namespace ipms::agent::windows {
namespace {
namespace json=hgs::json;
struct closer { void operator()(void* h)const { if(h && h!=INVALID_HANDLE_VALUE)CloseHandle(h); } };
using handle=std::unique_ptr<void,closer>;
[[noreturn]] void fail(){throw hgs::error("hgs_provider_failed");}
std::wstring wide(std::string_view text) {
  if(text.empty())return {};
  const auto count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
  if(count<=0)fail();std::wstring out(count,L'\0');
  if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),out.data(),count)!=count)fail();return out;
}
std::filesystem::path directory() { const auto path=gpo_storage_directory().parent_path()/L"hgs";ensure_gpo_directory(path);return path; }
bool protected_exists(const std::filesystem::path& path) {
  if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES)return true;
  if(GetLastError()!=ERROR_FILE_NOT_FOUND)fail();return false;
}
std::filesystem::path receipt_path(const hgs::job& assignment) {
  const auto path=directory()/L"receipts";ensure_gpo_directory(path);return path/(wide(assignment.text("job_id"))+L".json");
}
json::object adapter_call(const hgs::job& assignment,bool apply,const std::function<bool()>& cancelled) {
  (void)hgs::parse_job(assignment.fields);
  const auto root=directory();
  const auto script=root/(L"adapter-"+wide(gpo::sha256(hgs::adapter_content))+L".ps1");
  if(!protected_exists(script))write_protected_gpo_file(script,hgs::adapter_content,false);
  if(read_protected_gpo_file(script,256*1024)!=hgs::adapter_content)fail();
  // Request paths are generated locally and contain no job-selected path components.
  const auto request=root/L"request.json";
  auto local_assignment=assignment.fields;
  if(apply) {
    const auto expiry=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()+60;
    local_assignment["expires_at"]=(std::min)(assignment.fields.at("expires_at").as<std::int64_t>(),static_cast<std::int64_t>(expiry));
  }
  const auto bytes=json::serialize(json::object{{"mode",apply?"apply":"inspect"},{"assignment",std::move(local_assignment)}});
  write_protected_gpo_file(request,bytes,true);
  std::array<wchar_t,32768> system{};const auto count=GetSystemDirectoryW(system.data(),static_cast<UINT>(system.size()));
  if(!count || count>=system.size())fail();
  const auto executable=std::filesystem::path(system.data())/L"WindowsPowerShell"/L"v1.0"/L"powershell.exe";
  if(executable.wstring().find(L'"')!=std::wstring::npos || script.wstring().find(L'"')!=std::wstring::npos || request.wstring().find(L'"')!=std::wstring::npos)fail();
  std::wstring command=L"\""+executable.wstring()+L"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+script.wstring()+L"\" -RequestPath \""+request.wstring()+L"\"";
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE read{},write{};
  if(!CreatePipe(&read,&write,&sa,65536))fail();handle reader(read),writer(write);
  if(!SetHandleInformation(read,HANDLE_FLAG_INHERIT,0))fail();
  handle null(CreateFileW(L"NUL",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,nullptr));
  handle group(CreateJobObjectW(nullptr,nullptr));if(null.get()==INVALID_HANDLE_VALUE || !group)fail();
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_PROCESS_MEMORY;
  limits.ProcessMemoryLimit=1024ULL*1024*1024;
  if(!SetInformationJobObject(group.get(),JobObjectExtendedLimitInformation,&limits,sizeof(limits)))fail();
  SIZE_T attribute_bytes{};InitializeProcThreadAttributeList(nullptr,1,0,&attribute_bytes);std::vector<std::uint8_t> attributes(attribute_bytes);
  auto list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());if(!InitializeProcThreadAttributeList(list,1,0,&attribute_bytes))fail();
  struct release {LPPROC_THREAD_ATTRIBUTE_LIST value;~release(){DeleteProcThreadAttributeList(value);}} release_list{list};
  std::array<HANDLE,2> inherited{write,null.get()};
  if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited.data(),sizeof(inherited),nullptr,nullptr))fail();
  STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;startup.StartupInfo.hStdInput=null.get();startup.StartupInfo.hStdOutput=write;startup.StartupInfo.hStdError=null.get();startup.lpAttributeList=list;
  PROCESS_INFORMATION raw{};
  if(cancelled && cancelled())fail();
  if(!CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT,nullptr,root.c_str(),&startup.StartupInfo,&raw))fail();
  handle process(raw.hProcess),thread(raw.hThread);
  if(!AssignProcessToJobObject(group.get(),process.get())){TerminateProcess(process.get(),1);fail();}
  if(ResumeThread(thread.get())==static_cast<DWORD>(-1))fail();writer.reset();
  const auto deadline=std::chrono::steady_clock::now()+(apply?std::chrono::seconds(1800):std::chrono::seconds(120));
  std::string output;
  for(;;) {
    if((cancelled && cancelled()) || std::chrono::steady_clock::now()>deadline)fail();
    DWORD available{};
    if(!PeekNamedPipe(reader.get(),nullptr,0,nullptr,&available,nullptr) && GetLastError()!=ERROR_BROKEN_PIPE)fail();
    if(available) {
      std::array<char,8192> buffer{};DWORD read_bytes{};
      if(!ReadFile(reader.get(),buffer.data(),(std::min)(available,static_cast<DWORD>(buffer.size())),&read_bytes,nullptr))fail();
      if(output.size()+read_bytes>65536)fail();output.append(buffer.data(),read_bytes);
    }else if(WaitForSingleObject(process.get(),0)==WAIT_OBJECT_0) {
      DWORD exit_code{};if(!GetExitCodeProcess(process.get(),&exit_code)||exit_code!=0)fail();return json::parse(output).as<json::object>();
    }
    WaitForSingleObject(process.get(),50);
  }
}
class native_provider final:public hgs::provider {
  std::function<bool()> cancelled_;
  json::object last_observation_;
 public:
  explicit native_provider(std::function<bool()> cancelled):cancelled_(std::move(cancelled)){}
  json::object inspect(const hgs::job& j)override {
    auto result=adapter_call(j,false,cancelled_);hgs::validate_observation(result);
    const auto staged=directory()/L"staged-reboot.json";
    if(protected_exists(staged)) {
      const auto receipt=json::parse(read_protected_gpo_file(staged,4096)).as<json::object>();
      if(receipt.size()!=2 || !receipt.contains("boot_id") || !receipt.contains("job_id"))fail();
      if(receipt.at("boot_id")==result.at("boot_id"))result["reboot_pending"]=true;
    }
    last_observation_=result;return result;
  }
  void apply(const hgs::job& j)override {
    if(!hgs::unexpired(j) || (cancelled_ && cancelled_()))fail();
    if(j.text("operation")=="reboot") {
      if(!j.config().at("allow_reboot").as<bool>())fail();
      HANDLE raw{};if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&raw))fail();handle token(raw);
      TOKEN_PRIVILEGES privilege{};privilege.PrivilegeCount=1;
      if(!LookupPrivilegeValueW(nullptr,SE_SHUTDOWN_NAME,&privilege.Privileges[0].Luid))fail();privilege.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
      SetLastError(ERROR_SUCCESS);if(!AdjustTokenPrivileges(token.get(),FALSE,&privilege,0,nullptr,nullptr)||GetLastError()!=ERROR_SUCCESS)fail();
      wchar_t message[]=L"Approved IPMS HGS provisioning reboot.";
      const auto ok=InitiateSystemShutdownExW(nullptr,message,30,FALSE,TRUE,SHTDN_REASON_MAJOR_APPLICATION|SHTDN_REASON_MINOR_INSTALLATION|SHTDN_REASON_FLAG_PLANNED);
      privilege.Privileges[0].Attributes=0;AdjustTokenPrivileges(token.get(),FALSE,&privilege,0,nullptr,nullptr);
      if(!ok)fail();return;
    }
    if(j.config().at("node_role").as<std::string>()=="additional") {
      const auto address=wide(j.config().at("primary_server").as<std::string>());std::array<std::uint8_t,16> ip{};
      if(InetPtonW(AF_INET,address.c_str(),ip.data())!=1 && InetPtonW(AF_INET6,address.c_str(),ip.data())!=1)fail();
    }
    const auto response=adapter_call(j,true,cancelled_);
    if(response.size()!=2 || !response.at("applied").as<bool>())fail();
    if(response.at("reboot_required").as<bool>()) {
      if(last_observation_.empty())fail();
      write_protected_gpo_file(directory()/L"staged-reboot.json",json::serialize(json::object{{"boot_id",last_observation_.at("boot_id")},{"job_id",j.text("job_id")}}),true);
    }
  }
};
}
std::optional<hgs::journal> load_hgs_receipt(const hgs::job& assignment) {
  const auto path=receipt_path(assignment);if(!protected_exists(path))return std::nullopt;
  auto record=hgs::parse_journal(hgs::json::parse(read_protected_gpo_file(path,65536)));
  if(record.assignment!=assignment || record.state!=hgs::phase::terminal)fail();return record;
}
std::optional<hgs::journal> load_hgs_journal() {
  const auto path=directory()/L"current.json";if(!protected_exists(path))return std::nullopt;
  auto record=hgs::parse_journal(hgs::json::parse(read_protected_gpo_file(path,65536)));
  const auto receipt=load_hgs_receipt(record.assignment);
  if(receipt && receipt->outcome.at("status").as<std::string>()=="reconciliation_required")save_hgs_journal(*receipt);
  return receipt?receipt:std::optional<hgs::journal>(std::move(record));
}
void save_hgs_journal(const hgs::journal& record) {
  const auto document=hgs::journal_document(record);(void)hgs::parse_journal(document);const auto bytes=hgs::json::serialize(document);
  if(record.state==hgs::phase::terminal) {
    const auto path=receipt_path(record.assignment);
    if(protected_exists(path)){if(read_protected_gpo_file(path,65536)!=bytes)fail();}
    else write_protected_gpo_file(path,bytes,false);
    if(record.outcome.at("status").as<std::string>()=="reconciliation_required") {
      const auto previous=load_hgs_fence();if(previous && previous->assignment!=record.assignment)fail();
      write_protected_gpo_file(directory()/L"fence.json",bytes,true);
    }
  }
  write_protected_gpo_file(directory()/L"current.json",bytes,true);
}
std::optional<hgs::journal> load_hgs_fence() {
  const auto root=directory();const auto fence=root/L"fence.json";
  if(!protected_exists(fence))return std::nullopt;
  auto record=hgs::parse_journal(json::parse(read_protected_gpo_file(fence,65536)));
  if(record.state!=hgs::phase::terminal || record.outcome.at("status").as<std::string>()!="reconciliation_required")fail();
  const auto releases=root/L"releases";ensure_gpo_directory(releases);
  const auto path=releases/(wide(record.assignment.text("job_id"))+L".json");
  if(protected_exists(path)) {
    const auto expected=json::object{{"job_id",record.assignment.text("job_id")},{"plan_digest",record.assignment.text("plan_digest")}};
    if(json::parse(read_protected_gpo_file(path,4096))!=json::value(expected))fail();return std::nullopt;
  }
  return record;
}
void release_hgs_fence(const json::object& release) {
  if(release.size()!=2 || !release.contains("job_id") || !release.contains("plan_digest") || !gpo::valid_uuid(release.at("job_id").as<std::string>()))fail();
  const auto root=directory()/L"releases";ensure_gpo_directory(root);
  const auto path=root/(wide(release.at("job_id").as<std::string>())+L".json");
  const auto bytes=json::serialize(release);
  if(protected_exists(path)){if(read_protected_gpo_file(path,4096)!=bytes)fail();return;}
  const auto fence=load_hgs_fence();
  // A repeated older release can accompany a newly fenced job. It is irrelevant,
  // cannot release this fence, and must not suppress fresh read-only inspection.
  if(!fence || !hgs::release_matches(*fence,release))return;
  write_protected_gpo_file(path,bytes,false);
}
void* acquire_hgs_lock() {
  const auto path=directory()/L"cycle.lock";
  if(!protected_exists(path))try{write_protected_gpo_file(path,"",false);}catch(...){return nullptr;}
  (void)read_protected_gpo_file(path,1);
  handle lock(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
  return lock.get()==INVALID_HANDLE_VALUE?nullptr:lock.release();
}
std::unique_ptr<hgs::provider> make_hgs_provider(const std::function<bool()>& cancelled) {return std::make_unique<native_provider>(cancelled);}
}  // namespace ipms::agent::windows
