#include "ipms/agent/windows_management_journal.hpp"

#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <fstream>
#include <iostream>

namespace journal = ipms::agent::hyperv_management_journal;
namespace json = ipms::agent::management_json;
using namespace ipms::agent::windows;

int main() {
  SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
  PSID administrators = nullptr;
  BOOL member = FALSE;
  if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
      DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) return 1;
  CheckTokenMembership(nullptr, administrators, &member);
  FreeSid(administrators);
  if (!member) {
    std::cout << "SKIP: LocalSystem/administrator token is required for the protected journal I/O test.\n";
    return 77;
  }
  try {
    // CTest runs in its isolated build directory. Keep synthetic receipts for
    // inspection; no application/Agent data directory is touched or deleted.
    const auto base = std::filesystem::current_path() /
        (L"journal-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    if (!std::filesystem::create_directory(base)) return 2;
    const auto directory = base / L"journal";
    if (load_management_journal(directory)) return 3;
    const journal::binding binding{1, "11111111-1111-4111-8111-111111111111", std::string(64, 'a'),
        "urn:ipms:agent:22222222-2222-4222-8222-222222222222", journal::operation::checkpoint_create,
        "33333333-3333-4333-8333-333333333333"};
    const auto prepared = journal::prepare(binding);
    save_management_journal(directory, prepared);
    if (load_management_journal(directory) != prepared) return 4;
    const auto invoking = journal::begin_invocation(prepared);
    save_management_journal(directory, invoking);
    if (journal::recover(*load_management_journal(directory)).state != journal::phase::requires_reconciliation) return 5;
    bool blocked = false;
    try { archive_prepared_management_journal(directory, binding); } catch (...) { blocked = true; }
    if (!blocked || load_management_journal(directory) != invoking) return 6;
    const auto observing = journal::begin_observation(invoking, "Msvm_ConcreteJob.InstanceID=\"native-test\"");
    save_management_journal(directory, observing);
    // An uncommitted temporary write must never displace the known receipt.
    { std::ofstream temp(directory / L"current.new", std::ios::binary); temp << "incomplete"; }
    if (load_management_journal(directory) != observing) return 7;
    const auto terminal = journal::complete(observing, json::object{{"status", "failed"}, {"phase", "completed"}});
    save_management_journal(directory, terminal);
    if (load_management_journal(directory) != terminal) return 8;
    PSECURITY_DESCRIPTOR security = nullptr;
    PACL dacl = nullptr;
    if (GetNamedSecurityInfoW(const_cast<wchar_t*>((directory / L"current.json").c_str()),
        SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &security) != ERROR_SUCCESS) return 9;
    ACL_SIZE_INFORMATION information{};
    const bool protected_acl = dacl && GetAclInformation(dacl, &information, sizeof(information), AclSizeInformation) &&
                              information.AceCount == 2;
    bool safe_sids = protected_acl;
    for (DWORD index = 0; safe_sids && index < information.AceCount; ++index) {
      void* ace = nullptr;
      if (!GetAce(dacl, index, &ace) || static_cast<ACE_HEADER*>(ace)->AceType != ACCESS_ALLOWED_ACE_TYPE) { safe_sids = false; break; }
      const auto allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
      const auto sid = static_cast<PSID>(&allowed->SidStart);
      safe_sids = allowed->Mask == FILE_ALL_ACCESS &&
                  (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid));
    }
    LocalFree(security);
    if (!safe_sids) return 10;
    save_management_journal(directory, prepared);
    archive_prepared_management_journal(directory, binding);
    if (load_management_journal(directory) || !std::filesystem::is_regular_file(directory / L"last-cancelled.json")) return 11;
    { std::ofstream corrupt(directory / L"current.json", std::ios::binary); corrupt << "{broken"; }
    blocked = false;
    try { (void)load_management_journal(directory); } catch (...) { blocked = true; }
    if (!blocked) return 12;
    std::cout << "Protected Windows journal persistence, recovery, cancellation and corruption checks passed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "Protected journal I/O test failed: " << error.what() << '\n';
    return 13;
  }
}
