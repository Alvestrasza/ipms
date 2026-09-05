#include <windows.h>

#include "ipms/agent/windows_core_pack.hpp"
#include "ipms/agent/console_input_worker.hpp"
#include "ipms/agent/periodic_worker.hpp"
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
  ipms::agent::console_input_worker console_inputs(
      [](const auto& cancelled) {
        return ipms::agent::windows::run_console_input_cycle([&] {
          return cancelled() || WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
        });
      });
  ipms::agent::console_input_worker console_frames(
      [&console_inputs](const auto& cancelled) {
        const auto stopping = [&] {
          return cancelled() || WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
        };
        if (stopping()) return false;
        console_inputs.set_active(true);
        const auto frame = ipms::agent::windows::run_console_cycle(stopping);
        const bool active = !stopping() && frame.succeeded && frame.console_active;
        console_inputs.set_active(active);
        return active;
      }, std::chrono::milliseconds(150), std::chrono::milliseconds(25));
  ipms::agent::periodic_worker heartbeat(std::chrono::seconds(10),
      [](const auto& cancelled) {
        ipms::agent::windows::run_heartbeat_cycle([&] {
          return cancelled() || WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0;
        });
      });
  do {
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT) break;
    const ULONGLONG now = GetTickCount64();
    if (now >= next_inventory) {
      const auto inventory = ipms::agent::windows::run_inventory_cycle();
      next_inventory = now + (inventory.succeeded ? 300'000 : 10'000);
      if (inventory.succeeded && inventory.console_active) {
        // Main-thread responses may be old by now. They only wake a fresh
        // frame-channel poll, never apply an assignment or close a newer one.
        console_frames.set_active(true);
      }
    }
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT) break;
    if (now >= next_telemetry) {
      const auto telemetry = ipms::agent::windows::run_telemetry_cycle();
      next_telemetry = now + 10'000;
      if (telemetry.succeeded && telemetry.console_active) {
        console_frames.set_active(true);
      }
    }
    if (WaitForSingleObject(stop_event, 1'000) != WAIT_TIMEOUT) break;
  } while (true);
  heartbeat.stop();
  console_frames.stop();
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
