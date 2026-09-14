// File Name: windows_gpo_storage_tests.cpp
// Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Real local-file identity, ACL and hard-link boundaries without AD or Agent-state access.
#include "ipms/agent/windows_gpo_management.hpp"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <iostream>

using namespace ipms::agent::windows;
namespace {
void require(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F> void rejects(F f){bool denied=false;try{f();}catch(...){denied=true;}require(denied,"Unsafe filesystem object accepted");}
}
int main() {
  try {
    wchar_t temporary[MAX_PATH]{};require(GetTempPathW(MAX_PATH,temporary)>0,"No temporary directory");
    auto base=std::filesystem::absolute(std::filesystem::path(temporary));
    if(base.filename().empty())base=base.parent_path();
    const auto directory=base/(L"ipms-gpo-storage-test-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64()));
    require(directory.parent_path()==base,"Test path escaped temporary directory");
    const auto untrusted=std::filesystem::path(directory.wstring()+L".untrusted");
    {std::ofstream file(untrusted);file<<"untrusted";}
    rejects([&]{read_protected_gpo_file(untrusted,100);});
    if(!IsUserAnAdmin()){
      std::filesystem::create_directory(directory);
      rejects([&]{verify_gpo_storage_parent(directory);});
      std::filesystem::remove(directory);
      std::filesystem::remove(untrusted);
      std::cout<<"Untrusted-file rejection passed; privileged BA/SYSTEM storage checks require elevation and were skipped.\n";return 77;}
    ensure_gpo_directory(directory);
    verify_gpo_storage_parent(directory);
    const auto record=directory/L"record.json";
    write_protected_gpo_file(record,"first",false);require(read_protected_gpo_file(record,100)=="first","Initial readback mismatch");
    write_protected_gpo_file(record,"second",true);require(read_protected_gpo_file(record,100)=="second","Atomic replace failed");
    rejects([&]{read_protected_gpo_file(record,1);});
    const auto link=directory/L"hard-link.json";
    require(CreateHardLinkW(link.c_str(),record.c_str(),nullptr)!=0,"Cannot create disposable hard link");
    rejects([&]{read_protected_gpo_file(link,100);});
    rejects([&]{write_protected_gpo_file(link,"bad",false);});
    std::filesystem::remove(link);require(read_protected_gpo_file(record,100)=="second","Hard-link rejection changed original");
    rejects([&]{write_protected_gpo_file(record,"bad",false);});
    std::filesystem::remove(record);std::filesystem::remove(directory);std::filesystem::remove(untrusted);
    std::cout<<"GPO protected storage, replacement and hard-link checks passed without AD calls.\n";return 0;
  }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
