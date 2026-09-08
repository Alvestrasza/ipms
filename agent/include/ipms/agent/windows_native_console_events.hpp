#pragma once

#include <winsock2.h>
#include <windows.h>

#include <stdexcept>
#include <initializer_list>

namespace ipms::agent::windows {

// Owned by the shared callback state, not by the pump's stack: pending WinHTTP
// completions keep both wakeup handles alive until HANDLE_CLOSING.
class native_console_events {
 public:
  native_console_events() {
    handles_[0] = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    handles_[1] = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!handles_[0] || !handles_[1]) {
      close();
      throw std::runtime_error("The native console wakeup events are unavailable.");
    }
  }
  ~native_console_events() { close(); }
  native_console_events(const native_console_events&) = delete;
  native_console_events& operator=(const native_console_events&) = delete;

  void notify() noexcept { SetEvent(handles_[0]); }

  void watch(SOCKET socket) {
    // WSAEventSelect also makes the socket nonblocking. Subscribe before connect
    // so connect completion and incoming data cannot race with the first wait.
    if (WSAEventSelect(socket, handles_[1], FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE))
      throw std::runtime_error("The native console socket notifications are unavailable.");
  }

  void consume_network(SOCKET socket) {
    WSANETWORKEVENTS events{};
    // This atomically consumes the recorded events and resets their manual-reset
    // handle. A plain ResetEvent would lose notifications arriving concurrently.
    if (WSAEnumNetworkEvents(socket, handles_[1], &events))
      throw std::runtime_error("The native console socket notifications failed.");
    for (int bit : {FD_CONNECT_BIT, FD_READ_BIT, FD_WRITE_BIT, FD_CLOSE_BIT}) {
      if ((events.lNetworkEvents & (1L << bit)) && events.iErrorCode[bit])
        throw std::runtime_error("The local native console socket failed.");
    }
  }

  bool wait(DWORD timeout = 100) {
    const DWORD result = WaitForMultipleObjects(2, handles_, FALSE, timeout);
    if (result == WAIT_TIMEOUT) return false;
    if (result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 1) return true;
    throw std::runtime_error("The native console event wait failed.");
  }

 private:
  HANDLE handles_[2]{};
  void close() noexcept {
    for (auto handle : handles_) if (handle) CloseHandle(handle);
  }
};

}  // namespace ipms::agent::windows
