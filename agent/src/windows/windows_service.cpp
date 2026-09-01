#include <windows.h>

#include "ipms/agent/windows_core_pack.hpp"
#include "ipms/agent/windows_transport.hpp"

namespace {
SERVICE_STATUS_HANDLE status_handle = nullptr;
SERVICE_STATUS status{};
HANDLE stop_event = nullptr;

void report(DWORD state, DWORD exit_code = NO_ERROR) {
  status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.dwCurrentState = state;
  status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
  status.dwWin32ExitCode = exit_code;
  status.dwCheckPoint = 0;
  status.dwWaitHint = 0;
  SetServiceStatus(status_handle, &status);
}

DWORD WINAPI control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
  if (control == SERVICE_CONTROL_STOP && stop_event != nullptr) {
    report(SERVICE_STOP_PENDING);
    SetEvent(stop_event);
    return NO_ERROR;
  }
  return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI service_main(DWORD, LPWSTR*) {
  status_handle = RegisterServiceCtrlHandlerExW(L"IPMS Agent", control_handler, nullptr);
  if (status_handle == nullptr) return;
  report(SERVICE_START_PENDING);
  stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (stop_event == nullptr) { report(SERVICE_STOPPED, GetLastError()); return; }
  report(SERVICE_RUNNING);
  unsigned telemetry_cycles = 30;
  do {
    if (telemetry_cycles >= 30) {
      (void)ipms::agent::windows::run_inventory_cycle();
      telemetry_cycles = 0;
    }
    (void)ipms::agent::windows::run_telemetry_cycle();
    ++telemetry_cycles;
  } while (WaitForSingleObject(stop_event, 10'000) == WAIT_TIMEOUT);
  CloseHandle(stop_event);
  report(SERVICE_STOPPED);
}
}  // namespace

namespace ipms::agent::windows {
int run_windows_service() {
  SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(L"IPMS Agent"), service_main}, {nullptr, nullptr}};
  return StartServiceCtrlDispatcherW(table) ? 0 : static_cast<int>(GetLastError());
}
}  // namespace ipms::agent::windows
