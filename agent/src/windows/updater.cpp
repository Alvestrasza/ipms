#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
struct service_closer { void operator()(SC_HANDLE value) const { if (value) CloseServiceHandle(value); } };
using service_handle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, service_closer>;

bool safe_value(const std::wstring& value, std::size_t maximum = 64) {
  return !value.empty() && value.size() <= maximum &&
         std::all_of(value.begin(), value.end(), [](const wchar_t character) {
           return std::iswalnum(character) || character == L'-' || character == L'.' || character == L'_';
         });
}

std::array<unsigned, 3> version_tuple(const std::wstring& value) {
  std::array<unsigned, 3> result{};
  std::size_t position = 0;
  for (std::size_t index = 0; index < result.size(); ++index) {
    if (position >= value.size() || !std::iswdigit(value[position]))
      throw std::runtime_error("The updater version is invalid.");
    unsigned component = 0;
    while (position < value.size() && std::iswdigit(value[position])) {
      component = component * 10 + static_cast<unsigned>(value[position++] - L'0');
      if (component > 65'535) throw std::runtime_error("The updater version is invalid.");
    }
    result[index] = component;
    if (index + 1 < result.size()) {
      if (position >= value.size() || value[position++] != L'.')
        throw std::runtime_error("The updater version is invalid.");
    }
  }
  if (position != value.size()) throw std::runtime_error("The updater version is invalid.");
  return result;
}

std::wstring argument(int argc, wchar_t** argv, const std::wstring& name) {
  for (int index = 1; index + 1 < argc; index += 2) {
    if (argv[index] == name) return argv[index + 1];
  }
  throw std::runtime_error("A fixed updater argument is missing.");
}

std::filesystem::path executable_directory() {
  std::wstring buffer(32'768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) throw std::runtime_error("The updater path is unavailable.");
  buffer.resize(length);
  return std::filesystem::path(buffer).parent_path();
}

std::filesystem::path data_directory() {
  wchar_t program_data[MAX_PATH]{};
  const auto length = GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH);
  return (length == 0 ? std::filesystem::path(L"C:\\ProgramData") : std::filesystem::path(program_data)) /
         L"Alvestrasza" / L"IPMS Agent";
}

std::string narrow_ascii(const std::wstring& value) {
  if (!std::all_of(value.begin(), value.end(), [](wchar_t c) { return c >= 0x20 && c <= 0x7e; }))
    throw std::runtime_error("The updater value is not ASCII.");
  std::string result;
  result.reserve(value.size());
  for (const auto character : value) result.push_back(static_cast<char>(character));
  return result;
}

std::string hex(const unsigned char* bytes, std::size_t length) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (std::size_t index = 0; index < length; ++index)
    output << std::setw(2) << static_cast<unsigned>(bytes[index]);
  return output.str();
}

std::string file_sha256(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("The staged Agent binary is unavailable.");
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::array<unsigned char, 32> digest{};
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
    throw std::runtime_error("The updater SHA-256 provider is unavailable.");
  if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    throw std::runtime_error("The updater SHA-256 hash could not be created.");
  }
  std::array<char, 64 * 1024> buffer{};
  while (input) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto read = input.gcount();
    if (read > 0 && BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()),
                                   static_cast<ULONG>(read), 0) != 0) {
      BCryptDestroyHash(hash);
      BCryptCloseAlgorithmProvider(algorithm, 0);
      throw std::runtime_error("The updater could not hash the staged Agent binary.");
    }
  }
  const auto status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (status != 0) throw std::runtime_error("The updater could not finish the artifact digest.");
  return hex(digest.data(), digest.size());
}

service_handle open_service(DWORD access) {
  service_handle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) throw std::runtime_error("The Service Control Manager is unavailable.");
  service_handle service(OpenServiceW(manager.get(), L"IPMS Agent", access));
  if (!service) throw std::runtime_error("The IPMS Agent service is unavailable.");
  return service;
}

void stop_service() {
  auto service = open_service(SERVICE_STOP | SERVICE_QUERY_STATUS);
  SERVICE_STATUS status{};
  if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
    throw std::runtime_error("The Agent service could not be stopped.");
  for (unsigned attempt = 0; attempt < 120; ++attempt) {
    SERVICE_STATUS_PROCESS process_status{};
    DWORD bytes = 0;
    if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<BYTE*>(&process_status), sizeof(process_status), &bytes))
      throw std::runtime_error("The Agent service state could not be read.");
    if (process_status.dwCurrentState == SERVICE_STOPPED) return;
    Sleep(250);
  }
  throw std::runtime_error("The Agent service did not stop in time.");
}

void start_service() {
  auto service = open_service(SERVICE_START | SERVICE_QUERY_STATUS);
  if (!StartServiceW(service.get(), 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
    throw std::runtime_error("The Agent service could not be started.");
}

void write_result(const std::wstring& job, const std::string& result, const std::string& code) {
  const auto path = data_directory() / L"lifecycle-result.json";
  const auto temporary = path.wstring() + L".new";
  std::filesystem::create_directories(path.parent_path());
  const std::string document = "{\"job_id\":\"" + narrow_ascii(job) + "\",\"result\":\"" + result +
                               "\",\"result_code\":\"" + code + "\"}";
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("The lifecycle result could not be written.");
    output << document;
  }
  if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    throw std::runtime_error("The lifecycle result could not be committed.");
}

void set_display_version(const std::wstring& version) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IPMSAgent",
                    0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
    throw std::runtime_error("The Agent registration is unavailable.");
  const auto bytes = static_cast<DWORD>((version.size() + 1) * sizeof(wchar_t));
  const auto status = RegSetValueExW(key, L"DisplayVersion", 0, REG_SZ,
                                     reinterpret_cast<const BYTE*>(version.c_str()), bytes);
  RegCloseKey(key);
  if (status != ERROR_SUCCESS) throw std::runtime_error("The Agent registration could not be updated.");
}

std::wstring installed_version() {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IPMSAgent",
                    0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
    throw std::runtime_error("The Agent registration is unavailable.");
  std::array<wchar_t, 64> value{};
  DWORD type = 0;
  DWORD bytes = static_cast<DWORD>(value.size() * sizeof(wchar_t));
  const auto status = RegQueryValueExW(key, L"DisplayVersion", nullptr, &type,
                                       reinterpret_cast<BYTE*>(value.data()), &bytes);
  RegCloseKey(key);
  if (status != ERROR_SUCCESS || type != REG_SZ || bytes < sizeof(wchar_t) || value.back() != L'\0')
    throw std::runtime_error("The installed Agent version is unavailable.");
  return value.data();
}

int report_uninstall(const std::filesystem::path& agent, const std::wstring& job,
                     const std::wstring& result, const std::wstring& code) {
  std::wstring command = L"\"" + agent.wstring() + L"\" --report-lifecycle-result \"" + job +
                         L"\" \"" + result + L"\" \"" + code + L"\"";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                      agent.parent_path().c_str(), &startup, &process)) return 1;
  WaitForSingleObject(process.hProcess, 60'000);
  DWORD exit_code = 1;
  GetExitCodeProcess(process.hProcess, &exit_code);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return static_cast<int>(exit_code);
}

void remove_registration() {
  auto service = open_service(DELETE);
  if (!DeleteService(service.get()) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
    throw std::runtime_error("The Agent service registration could not be removed.");
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IPMSAgent");
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace\\{4B13D2F1-A647-4D4E-B0D7-7EE33E72F691}");
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"Software\\Classes\\CLSID\\{4B13D2F1-A647-4D4E-B0D7-7EE33E72F691}");
  const auto shortcut = std::filesystem::path(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\IPMS Agent");
  std::error_code ignored;
  std::filesystem::remove_all(shortcut, ignored);
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  try {
    if (argc != 11) throw std::runtime_error("The fixed updater invocation is invalid.");
    const auto job = argument(argc, argv, L"--job");
    const auto action = argument(argc, argv, L"--action");
    const auto version = argument(argc, argv, L"--version");
    const auto expected_sha256 = argument(argc, argv, L"--sha256");
    const auto staged = std::filesystem::path(argument(argc, argv, L"--staged"));
    if (!safe_value(job) || (action != L"update" && action != L"uninstall"))
      throw std::runtime_error("The fixed updater invocation is invalid.");
    const auto install = executable_directory();
    const auto agent = install / L"ipms-agent.exe";
    stop_service();
    if (action == L"update") {
      if (!safe_value(version) || expected_sha256.size() != 64 ||
          !std::all_of(expected_sha256.begin(), expected_sha256.end(), [](wchar_t c) { return std::iswxdigit(c); }))
        throw std::runtime_error("The fixed update policy is invalid.");
      if (version_tuple(version) <= version_tuple(installed_version()))
        throw std::runtime_error("The fixed update policy rejected a non-monotonic version.");
      if (file_sha256(staged) != narrow_ascii(expected_sha256))
        throw std::runtime_error("The staged Agent binary failed verification.");
      const auto backup = install / L"ipms-agent.exe.rollback";
      if (!CopyFileW(agent.c_str(), backup.c_str(), FALSE))
        throw std::runtime_error("The current Agent binary could not be backed up.");
      if (!MoveFileExW(staged.c_str(), agent.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("The Agent binary could not be replaced.");
      try {
        set_display_version(version);
        write_result(job, "succeeded", "updated");
        start_service();
        std::error_code ignored;
        std::filesystem::remove(backup, ignored);
      } catch (...) {
        MoveFileExW(backup.c_str(), agent.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        write_result(job, "failed", "update_rolled_back");
        start_service();
        throw;
      }
      return 0;
    }
    remove_registration();
    for (const auto* name : {L"ipms-agent-config.exe", L"ipms-agent-import-enrollment.ps1",
                             L"ipms-agent-uninstall.ps1", L"install-windows-agent.ps1"}) {
      std::error_code ignored;
      std::filesystem::remove(install / name, ignored);
    }
    if (report_uninstall(agent, job, L"succeeded", L"uninstalled") != 0)
      throw std::runtime_error("The Agent uninstall result could not be delivered.");
    MoveFileExW(agent.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    wchar_t updater_path[32'768]{};
    if (GetModuleFileNameW(nullptr, updater_path, static_cast<DWORD>(std::size(updater_path))) != 0)
      MoveFileExW(updater_path, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    return 0;
  } catch (...) {
    return 1;
  }
}
