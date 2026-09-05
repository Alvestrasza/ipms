#include <windows.h>

#include "ipms/agent/windows_core_pack.hpp"
#include "ipms/agent/console_input_worker.hpp"
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
  ULONGLONG next_inventory = 0;
  ULONGLONG next_telemetry = 0;
  bool console_active = false;
  ipms::agent::console_input_worker console_inputs(
      [](const auto& cancelled) {
        return ipms::agent::windows::run_console_input_cycle([&] {
          return cancelled() || WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
        });
      });
  do {
    const ULONGLONG now = GetTickCount64();
    if (!console_active && now >= next_inventory) {
      const auto inventory = ipms::agent::windows::run_inventory_cycle();
      next_inventory = now + (inventory.succeeded ? 300'000 : 10'000);
      if (inventory.succeeded) {
        console_active = inventory.console_active;
      }
    }
    if (!console_active && now >= next_telemetry) {
      const auto telemetry = ipms::agent::windows::run_telemetry_cycle();
      next_telemetry = now + 10'000;
      if (telemetry.succeeded) {
        console_active = telemetry.console_active;
      }
    }
    if (console_active) {
      console_inputs.set_active(true);
      const auto console = ipms::agent::windows::run_console_cycle();
      console_active = console.succeeded && console.console_active;
    }
    console_inputs.set_active(console_active);
    // A bounded 150 ms cadence includes work time; avoid adding a full sleep
    // after every capture and mTLS exchange. Keep a yield on busy hosts.
    const ULONGLONG elapsed = GetTickCount64() - now;
    const DWORD interval = console_active
        ? static_cast<DWORD>(elapsed < 125 ? 150 - elapsed : 25)
        : 1'000;
    if (WaitForSingleObject(stop_event, interval) != WAIT_TIMEOUT) break;
  } while (true);
  console_inputs.stop();
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
