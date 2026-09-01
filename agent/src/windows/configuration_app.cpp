#include <windows.h>

#include "ipms/agent/configuration.hpp"
#include "ipms/agent/management_pack.hpp"
#include "resources/resource.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace {
constexpr int k_gateway_host = 1001;
constexpr int k_gateway_port = 1002;
constexpr int k_trust_mode = 1003;
constexpr int k_save = 1004;
constexpr int k_reload = 1005;
constexpr int k_overview = 2000;

std::filesystem::path configuration_path() {
  wchar_t program_data[MAX_PATH]{};
  const auto length = GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH);
  const std::filesystem::path base = length == 0 ? L"C:\\ProgramData" : program_data;
  return base / L"Alvestrasza" / L"IPMS Agent" / L"agent-settings.ini";
}

std::wstring trim(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) return L"";
  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

ipms::agent::AgentConfiguration load_configuration() {
  ipms::agent::AgentConfiguration configuration{};
  std::wifstream input(configuration_path());
  std::wstring line;
  while (std::getline(input, line)) {
    const auto separator = line.find(L'=');
    if (separator == std::wstring::npos) continue;
    const auto key = trim(line.substr(0, separator));
    const auto value = trim(line.substr(separator + 1));
    if (key == L"gateway_hostname") configuration.gateway_hostname = value;
    if (key == L"gateway_port") {
      try {
        const auto port = std::stoul(value);
        if (port <= 65535) configuration.gateway_port = static_cast<std::uint16_t>(port);
      } catch (...) { }
    }
    if (key == L"trust_mode") configuration.trust_mode = ipms::agent::parse_trust_mode(value);
  }
  return configuration;
}

bool save_configuration_atomically(const ipms::agent::AgentConfiguration& configuration) {
  if (!ipms::agent::is_valid_agent_configuration(configuration)) return false;
  const auto path = configuration_path();
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) return false;
  const auto temporary = path.wstring() + L".new";
  {
    std::wofstream output(temporary, std::ios::trunc);
    if (!output) return false;
    output << L"gateway_hostname=" << configuration.gateway_hostname << L"\n";
    output << L"gateway_port=" << configuration.gateway_port << L"\n";
    output << L"trust_mode=" << ipms::agent::trust_mode_name(configuration.trust_mode) << L"\n";
    output.flush();
    if (!output) return false;
  }
  return MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
}

bool is_administrator() {
  SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
  PSID administrators = nullptr;
  BOOL member = FALSE;
  if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                               0, 0, 0, 0, 0, 0, &administrators)) {
    CheckTokenMembership(nullptr, administrators, &member);
    FreeSid(administrators);
  }
  return member != FALSE;
}

std::wstring service_state() {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) return L"Not installed";
  SC_HANDLE service = OpenServiceW(manager, L"IPMS Agent", SERVICE_QUERY_STATUS);
  if (service == nullptr) { CloseServiceHandle(manager); return L"Not installed"; }
  SERVICE_STATUS_PROCESS status{};
  DWORD required = 0;
  const bool queried = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                              reinterpret_cast<LPBYTE>(&status), sizeof(status), &required) != FALSE;
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (!queried) return L"Unknown";
  return status.dwCurrentState == SERVICE_RUNNING ? L"Running" : L"Stopped";
}

void set_text(HWND window, int id, const std::wstring& value) {
  SetWindowTextW(GetDlgItem(window, id), value.c_str());
}

std::wstring get_text(HWND window, int id) {
  const auto control = GetDlgItem(window, id);
  const auto length = GetWindowTextLengthW(control);
  std::wstring value(length + 1, L'\0');
  GetWindowTextW(control, value.data(), length + 1);
  value.resize(length);
  return trim(value);
}

void render_configuration(HWND window) {
  const auto configuration = load_configuration();
  set_text(window, k_gateway_host, configuration.gateway_hostname);
  set_text(window, k_gateway_port, std::to_wstring(configuration.gateway_port));
  SendDlgItemMessageW(window, k_trust_mode, CB_SETCURSEL, static_cast<WPARAM>(configuration.trust_mode), 0);
  std::wostringstream overview;
  overview << L"Service: " << service_state() << L"\r\n"
           << L"Gateway channel: agent-initiated, bidirectional mTLS\r\n"
           << L"Certificate: Not enrolled (PKI and Gateway pending)\r\n"
           << L"Active built-in packs: windows-server-core, hyper-v-host\r\n"
           << L"Configuration file: " << configuration_path().wstring();
  set_text(window, k_overview, overview.str());
}

void save_from_window(HWND window) {
  if (!is_administrator()) {
    MessageBoxW(window, L"Run this application as an administrator to change Agent settings.", L"IPMS Agent Configuration", MB_ICONWARNING);
    return;
  }
  ipms::agent::AgentConfiguration configuration{};
  configuration.gateway_hostname = get_text(window, k_gateway_host);
  try {
    const auto port = std::stoul(get_text(window, k_gateway_port));
    if (port > 65535) throw std::out_of_range("port");
    configuration.gateway_port = static_cast<std::uint16_t>(port);
  } catch (...) {
    MessageBoxW(window, L"Gateway port must be between 1 and 65535.", L"IPMS Agent Configuration", MB_ICONERROR);
    return;
  }
  const auto selection = SendDlgItemMessageW(window, k_trust_mode, CB_GETCURSEL, 0, 0);
  configuration.trust_mode = selection == 1 ? ipms::agent::TrustMode::external_issuing_ca :
                             selection == 2 ? ipms::agent::TrustMode::external_certificates :
                                              ipms::agent::TrustMode::ipms_managed;
  if (!save_configuration_atomically(configuration)) {
    MessageBoxW(window, L"The configuration could not be saved. Check the path and administrator permissions.", L"IPMS Agent Configuration", MB_ICONERROR);
    return;
  }
  render_configuration(window);
  MessageBoxW(window, L"Settings were saved atomically. mTLS validation starts after enrollment support is installed.", L"IPMS Agent Configuration", MB_ICONINFORMATION);
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
  switch (message) {
    case WM_CREATE: {
      CreateWindowW(L"STATIC", L"Management Server", WS_CHILD | WS_VISIBLE, 20, 20, 160, 20, window, nullptr, nullptr, nullptr);
      CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 190, 18, 400, 24, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(k_gateway_host)), nullptr, nullptr);
      CreateWindowW(L"STATIC", L"Gateway Port", WS_CHILD | WS_VISIBLE, 20, 55, 160, 20, window, nullptr, nullptr, nullptr);
      CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"9419", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 190, 53, 120, 24, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(k_gateway_port)), nullptr, nullptr);
      CreateWindowW(L"STATIC", L"Trust Mode", WS_CHILD | WS_VISIBLE, 20, 90, 160, 20, window, nullptr, nullptr, nullptr);
      const auto mode = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST, 190, 88, 220, 100, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(k_trust_mode)), nullptr, nullptr);
      SendMessageW(mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"IPMS managed PKI"));
      SendMessageW(mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"External issuing CA"));
      SendMessageW(mode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"External certificates"));
      CreateWindowW(L"BUTTON", L"Save", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 430, 88, 75, 25, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(k_save)), nullptr, nullptr);
      CreateWindowW(L"BUTTON", L"Reload", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 515, 88, 75, 25, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(k_reload)), nullptr, nullptr);
      CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 20, 135, 570, 155, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(k_overview)), nullptr, nullptr);
      render_configuration(window);
      return 0;
    }
    case WM_COMMAND:
      if (LOWORD(w_param) == k_save) { save_from_window(window); return 0; }
      if (LOWORD(w_param) == k_reload) { render_configuration(window); return 0; }
      break;
    case WM_DESTROY: PostQuitMessage(0); return 0;
  }
  return DefWindowProcW(window, message, w_param, l_param);
}
}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int command_show) {
  constexpr wchar_t class_name[] = L"IPMSAgentConfiguration";
  WNDCLASSW window_class{};
  window_class.hInstance = instance;
  window_class.lpszClassName = class_name;
  window_class.lpfnWndProc = window_proc;
  window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  window_class.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_IPMS_AGENT));
  window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  RegisterClassW(&window_class);
  const auto window = CreateWindowExW(0, class_name, L"IPMS Agent Configuration", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                       CW_USEDEFAULT, CW_USEDEFAULT, 630, 350, nullptr, nullptr, instance, nullptr);
  SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_IPMS_AGENT), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR)));
  ShowWindow(window, command_show);
  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
  return static_cast<int>(message.wParam);
}
