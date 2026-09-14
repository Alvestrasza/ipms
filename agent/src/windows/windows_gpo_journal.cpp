// File Name: windows_gpo_journal.cpp
// Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Protected exact-job approval, immutable package staging and durable GPO fences.
#include "ipms/agent/windows_gpo_management.hpp"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <array>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>

namespace ipms::agent::windows {
namespace {
namespace json = gpo::json;
struct closer { void operator()(void* p) const { if(p && p!=INVALID_HANDLE_VALUE) CloseHandle(p); } };
using handle = std::unique_ptr<void,closer>;
struct local_free { void operator()(void* p) const { if(p) LocalFree(p); } };
using local_ptr = std::unique_ptr<void,local_free>;
[[noreturn]] void unsafe() { throw gpo::operation_error("gpo_journal_invalid"); }
bool trusted_sid(PSID sid) { return sid && (IsWellKnownSid(sid,WinLocalSystemSid)||IsWellKnownSid(sid,WinBuiltinAdministratorsSid)); }
void protected_handle(HANDLE file,bool directory,bool container=false) {
  BY_HANDLE_FILE_INFORMATION info{};
  if(!GetFileInformationByHandle(file,&info) || (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) ||
      static_cast<bool>(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory || (!directory&&info.nNumberOfLinks!=1)) unsafe();
  PSID owner{}; PACL acl{}; PSECURITY_DESCRIPTOR raw{};
  if(GetSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&raw)!=ERROR_SUCCESS) unsafe();
  local_ptr descriptor(raw);
  if(!trusted_sid(owner)||!acl) unsafe();
  for(DWORD i=0;i<acl->AceCount;++i) {
    void* ace{}; if(!GetAce(acl,i,&ace)) unsafe();
    const auto* header=static_cast<ACE_HEADER*>(ace);
    if(container&&(header->AceFlags&INHERIT_ONLY_ACE)) continue;
    if(container&&header->AceType==ACCESS_DENIED_ACE_TYPE) continue;
    if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE) unsafe();
    const auto* allowed=static_cast<ACCESS_ALLOWED_ACE*>(ace);
    // ProgramData permits ordinary users to create their own children. That
    // does not permit replacing this already protected child. Delete-child,
    // owner and DACL control on a parent would permit such a replacement.
    constexpr DWORD replacement=DELETE|WRITE_DAC|WRITE_OWNER|FILE_DELETE_CHILD|GENERIC_ALL;
    if(!trusted_sid(const_cast<DWORD*>(&allowed->SidStart))&&(!container||(allowed->Mask&replacement))) unsafe();
  }
}
void no_reparse_ancestors(std::filesystem::path path) {
  if(!path.is_absolute()) unsafe();
  for(;!path.empty();) {
    const auto a=GetFileAttributesW(path.c_str());
    if(a==INVALID_FILE_ATTRIBUTES || !(a&FILE_ATTRIBUTE_DIRECTORY) || (a&FILE_ATTRIBUTE_REPARSE_POINT)) unsafe();
    auto parent=path.parent_path(); if(parent==path) break; path=std::move(parent);
  }
}
local_ptr descriptor() {
  PSECURITY_DESCRIPTOR raw{};
  if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",SDDL_REVISION_1,&raw,nullptr)) unsafe();
  return local_ptr(raw);
}
std::filesystem::path agent_directory() {
  PWSTR raw{}; if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData,0,nullptr,&raw))) unsafe();
  std::filesystem::path path(raw); CoTaskMemFree(raw);
  verify_gpo_storage_parent(path);
  path/=L"Alvestrasza";verify_gpo_storage_parent(path);
  path/=L"IPMS Agent";verify_gpo_storage_parent(path);
  return path;
}
std::wstring wide(std::string_view s) {
  const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
  if(!n) unsafe(); std::wstring out(n,L'\0');
  if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n)!=n) unsafe(); return out;
}
std::filesystem::path job_directory(const gpo::job& j) {
  const auto root=gpo_storage_directory(); ensure_gpo_directory(root);
  const auto path=root/wide(j.text("job_id")); ensure_gpo_directory(path); return path;
}
json::object approval(const gpo::job& j,std::string_view uri) {
  return {{"schema",1},{"job",j.fields},{"device_uri",uri}};
}
std::string enrollment() {
  const auto content=read_protected_gpo_file(agent_directory()/L"agent-state.json",65536);
  return json::parse(content).as<json::object>().at("device_uri").as<std::string>();
}
bool elevated() {
  handle token; HANDLE raw{};
  if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)) return false; token.reset(raw);
  TOKEN_ELEVATION elevation{}; DWORD read{};
  if(!GetTokenInformation(token.get(),TokenElevation,&elevation,sizeof(elevation),&read)||!elevation.TokenIsElevated) return false;
  std::array<std::uint8_t,SECURITY_MAX_SID_SIZE> bytes{}; DWORD length=static_cast<DWORD>(bytes.size());
  if(!CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,bytes.data(),&length)) return false;
  BOOL member{}; return CheckTokenMembership(nullptr,bytes.data(),&member)&&member;
}
}  // namespace

void verify_gpo_storage_parent(const std::filesystem::path& directory) {
  no_reparse_ancestors(directory);
  handle dir(CreateFileW(directory.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
    nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
  if(dir.get()==INVALID_HANDLE_VALUE) unsafe();protected_handle(dir.get(),true,true);
}
void ensure_gpo_directory(const std::filesystem::path& directory) {
  no_reparse_ancestors(directory.parent_path());
  const auto sd=descriptor(); SECURITY_ATTRIBUTES sa{sizeof(sa),sd.get(),FALSE};
  if(!CreateDirectoryW(directory.c_str(),&sa)&&GetLastError()!=ERROR_ALREADY_EXISTS) unsafe();
  handle dir(CreateFileW(directory.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
    nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
  if(dir.get()==INVALID_HANDLE_VALUE) unsafe(); protected_handle(dir.get(),true);
}
std::string read_protected_gpo_file(const std::filesystem::path& path,std::size_t limit) {
  no_reparse_ancestors(path.parent_path());
  handle file(CreateFileW(path.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
  if(file.get()==INVALID_HANDLE_VALUE) unsafe(); protected_handle(file.get(),false);
  LARGE_INTEGER size{}; if(!GetFileSizeEx(file.get(),&size)||size.QuadPart<0||static_cast<std::uint64_t>(size.QuadPart)>limit) unsafe();
  std::string out(static_cast<std::size_t>(size.QuadPart),'\0'); DWORD read{};
  if(!out.empty()&&(!ReadFile(file.get(),out.data(),static_cast<DWORD>(out.size()),&read,nullptr)||read!=out.size())) unsafe();
  return out;
}
void write_protected_gpo_file(const std::filesystem::path& path,std::string_view bytes,bool replace) {
  ensure_gpo_directory(path.parent_path());
  const auto sd=descriptor(); SECURITY_ATTRIBUTES sa{sizeof(sa),sd.get(),FALSE};
  const auto target=replace?std::filesystem::path(path.wstring()+L".new"):path;
  // Never follow or truncate an existing attacker-controlled entry.
  handle file(CreateFileW(target.c_str(),GENERIC_WRITE|READ_CONTROL,0,&sa,CREATE_NEW,
      FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr));
  if(file.get()==INVALID_HANDLE_VALUE) unsafe(); protected_handle(file.get(),false);
  DWORD written{};
  if((!bytes.empty()&&(!WriteFile(file.get(),bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)||written!=bytes.size()))||!FlushFileBuffers(file.get())) unsafe();
  file.reset();
  if(replace) {
    const auto attrs=GetFileAttributesW(path.c_str());
    if(attrs!=INVALID_FILE_ATTRIBUTES) (void)read_protected_gpo_file(path,gpo::maximum_artifact_bytes);
    if(!MoveFileExW(target.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) unsafe();
  }
}
std::filesystem::path gpo_storage_directory() { return agent_directory()/L"gpo-management"; }
std::optional<gpo::journal> load_gpo_journal() {
  const auto root=gpo_storage_directory(); ensure_gpo_directory(root); const auto path=root/L"current.json";
  if(GetFileAttributesW(path.c_str())==INVALID_FILE_ATTRIBUTES) {
    if(GetLastError()==ERROR_FILE_NOT_FOUND) return std::nullopt; unsafe();
  }
  auto record=gpo::parse_journal(json::parse(read_protected_gpo_file(path,65536)));
  // The immutable receipt is flushed before current.json is replaced. A crash
  // between those writes must replay the known outcome, never repeat AD work.
  const auto receipt=job_directory(record.assignment)/L"receipt.json";
  if(GetFileAttributesW(receipt.c_str())!=INVALID_FILE_ATTRIBUTES) {
    auto completed=gpo::parse_journal(json::parse(read_protected_gpo_file(receipt,65536)));
    if(completed.assignment!=record.assignment||completed.device_uri!=record.device_uri||
        (completed.state!=gpo::phase::terminal&&completed.state!=gpo::phase::reconciliation)) unsafe();
    return completed;
  }
  return record;
}
void save_gpo_journal(const gpo::journal& record) {
  const auto document=gpo::journal_document(record); (void)gpo::parse_journal(document);
  const auto serialized=json::serialize(document);
  if(record.state==gpo::phase::terminal||record.state==gpo::phase::reconciliation) {
    const auto receipt=job_directory(record.assignment)/L"receipt.json";
    if(GetFileAttributesW(receipt.c_str())!=INVALID_FILE_ATTRIBUTES) {
      if(read_protected_gpo_file(receipt,65536)!=serialized) unsafe();
    }else write_protected_gpo_file(receipt,serialized,false);
  }
  const auto root=gpo_storage_directory(); ensure_gpo_directory(root);
  write_protected_gpo_file(root/L"current.json",serialized,true);
}
bool gpo_enrollment_matches(std::string_view uri) { try { return enrollment()==uri; } catch(...) { return false; } }
bool has_gpo_local_approval(const gpo::job& j,std::string_view uri) { try {
  if(!gpo::unexpired(j)||!gpo_enrollment_matches(uri)) return false;
  const auto path=job_directory(j);
  if(GetFileAttributesW((path/L"approval-consumed.json").c_str())!=INVALID_FILE_ATTRIBUTES) return false;
  return json::parse(read_protected_gpo_file(path/L"approval.json",65536))==json::value(approval(j,uri));
} catch(...) { return false; } }
void consume_gpo_local_approval(const gpo::job& j,std::string_view uri) {
  if(!has_gpo_local_approval(j,uri)) throw gpo::operation_error("gpo_local_approval_invalid");
  const auto path=job_directory(j);
  if(!MoveFileExW((path/L"approval.json").c_str(),(path/L"approval-consumed.json").c_str(),MOVEFILE_WRITE_THROUGH))
    throw gpo::operation_error("gpo_local_approval_invalid");
}
void save_gpo_artifact(const gpo::job& j,std::string_view bytes) {
  const auto* c=gpo::component(j); if(!c) throw gpo::operation_error("gpo_unsupported_component");
  (void)gpo::decode_artifact(*c,{reinterpret_cast<const std::uint8_t*>(bytes.data()),bytes.size()});
  const auto path=job_directory(j)/L"artifact.bin";
  if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES) {
    if(read_protected_gpo_file(path,gpo::maximum_artifact_bytes)!=bytes) throw gpo::operation_error("gpo_artifact_invalid");
  } else write_protected_gpo_file(path,bytes,false);
}
std::filesystem::path expand_gpo_artifact(const gpo::job& j) {
  const auto* c=gpo::component(j); if(!c) throw gpo::operation_error("gpo_unsupported_component");
  const auto root=job_directory(j); const auto artifact=read_protected_gpo_file(root/L"artifact.bin",gpo::maximum_artifact_bytes);
  const auto files=gpo::decode_artifact(*c,{reinterpret_cast<const std::uint8_t*>(artifact.data()),artifact.size()});
  const auto backups=root/L"backups"; ensure_gpo_directory(backups);
  const auto component_root=backups/wide(c->backup_id); ensure_gpo_directory(component_root);
  std::set<std::filesystem::path> expected;
  for(const auto entry:c->directories) {
    const std::filesystem::path relative(wide(entry));
    if(relative.is_absolute()||relative.has_root_name()) unsafe();
    auto current=component_root;
    for(const auto& part:relative) {
      if(part==L".."||part==L".") unsafe(); current/=part; ensure_gpo_directory(current);
      expected.insert(current.lexically_relative(component_root));
    }
  }
  for(std::size_t i=0;i<files.size();++i) {
    const std::filesystem::path relative(wide(c->files[i].relative_path));
    if(relative.is_absolute()||relative.has_root_name()) unsafe();
    auto current=component_root;
    for(const auto& part:relative.parent_path()) { if(part==L".."||part==L".") unsafe(); current/=part; ensure_gpo_directory(current); }
    const auto path=component_root/relative;
    expected.insert(relative);
    const std::string_view content(reinterpret_cast<const char*>(files[i].data()),files[i].size());
    if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES) {
      if(read_protected_gpo_file(path,gpo::maximum_file_bytes)!=content) throw gpo::operation_error("gpo_artifact_invalid");
    } else write_protected_gpo_file(path,content,false);
  }
  std::size_t seen=0;
  for(const auto& entry:std::filesystem::recursive_directory_iterator(component_root)) {
    const auto a=GetFileAttributesW(entry.path().c_str());
    if(a==INVALID_FILE_ATTRIBUTES||(a&FILE_ATTRIBUTE_REPARSE_POINT)||!expected.contains(entry.path().lexically_relative(component_root))) unsafe();
    ++seen;
  }
  if(seen!=expected.size()) unsafe();
  return backups;
}
void* acquire_gpo_cycle_lock() {
  const auto root=gpo_storage_directory(); ensure_gpo_directory(root);
  const auto sd=descriptor(); SECURITY_ATTRIBUTES sa{sizeof(sa),sd.get(),FALSE};
  handle h(CreateFileW((root/L"current.lock").c_str(),GENERIC_READ|GENERIC_WRITE|READ_CONTROL,0,&sa,OPEN_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
  if(h.get()==INVALID_HANDLE_VALUE) return nullptr; protected_handle(h.get(),false); return h.release();
}
int approve_gpo_pilot(const std::filesystem::path& document) {
  try {
    if(!elevated()) { std::cerr<<"An elevated local administrator must approve this exact pilot job.\n"; return 5; }
    // This is a locally supplied review document, never a server-selected path.
    const auto size=std::filesystem::file_size(document); if(size==0||size>65536) unsafe();
    std::ifstream input(document,std::ios::binary); if(!input) unsafe();
    std::string text(static_cast<std::size_t>(size),'\0'); input.read(text.data(),static_cast<std::streamsize>(text.size()));
    if(!input||input.peek()!=std::char_traits<char>::eof()) unsafe();
    const auto j=gpo::parse_job(json::parse(text));
    if(!gpo::unexpired(j)||!gpo::component(j)) throw gpo::operation_error("gpo_invalid_job");
    const auto uri=enrollment(); const auto root=job_directory(j);
    if(GetFileAttributesW((root/L"approval-consumed.json").c_str())!=INVALID_FILE_ATTRIBUTES)
      throw gpo::operation_error("gpo_reconciliation_required");
    write_protected_gpo_file(root/L"approval.json",json::serialize(approval(j,uri)),false);
    if(!has_gpo_local_approval(j,uri)) unsafe();
    std::cout<<"Approved exact unlinked pilot job "<<j.text("job_id")<<" with digest "<<j.text("input_digest")<<" until "<<j.text("expires_at")<<".\n";
    return 0;
  } catch(const std::exception&) { std::cerr<<"Pilot approval failed; no AD operation was performed.\n"; return 4; }
}
}  // namespace ipms::agent::windows
