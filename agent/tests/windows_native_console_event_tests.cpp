#include <winsock2.h>
#include <windows.h>

#include "ipms/agent/windows_native_console_events.hpp"

#include <array>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace std::chrono_literals;

void require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}

struct winsock_scope {
  winsock_scope() {
    WSADATA runtime{};
    require(WSAStartup(MAKEWORD(2, 2), &runtime) == 0, "Winsock unavailable");
  }
  ~winsock_scope() { WSACleanup(); }
};
struct socket_scope {
  SOCKET value{INVALID_SOCKET};
  ~socket_scope() { close(); }
  void close() { if (value != INVALID_SOCKET) closesocket(value); value = INVALID_SOCKET; }
  operator SOCKET() const { return value; }
};

int main() {
  try {
    winsock_scope runtime;
    ipms::agent::windows::native_console_events events;
    // A completion between the state check and wait must not be lost.
    events.notify();
    auto started = std::chrono::steady_clock::now();
    require(events.wait(1000), "A queued completion was lost");
    require(std::chrono::steady_clock::now() - started < 500ms,
            "A queued completion waited for a polling deadline");
    require(!events.wait(20), "Completion notification did not auto-reset");

    auto pending = std::async(std::launch::async, [&] { return events.wait(2000); });
    events.notify();
    require(pending.wait_for(500ms) == std::future_status::ready && pending.get(),
            "A callback did not wake a waiting relay");

    socket_scope listener{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    require(listener != INVALID_SOCKET, "Fixture listener unavailable");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
            "Fixture bind failed");
    int size = sizeof(address);
    require(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size) == 0 &&
            listen(listener, 1) == 0, "Fixture listen failed");
    socket_scope peer{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    require(connect(peer, reinterpret_cast<sockaddr*>(&address), size) == 0,
            "Fixture connect failed");
    socket_scope local{accept(listener, nullptr, nullptr)};
    require(local != INVALID_SOCKET, "Fixture accept failed");
    events.watch(local);
    events.consume_network(local); // Initial FD_WRITE is not incoming data.
    require(send(peer, "wake", 4, 0) == 4, "Fixture send failed");
    require(events.wait(1000), "Socket readability did not wake the relay");
    events.consume_network(local);
    std::array<char, 8> data{};
    require(recv(local, data.data(), static_cast<int>(data.size()), 0) == 4,
            "The woken relay could not receive data");
    // Re-arming readiness after recv must also wake on the next packet.
    events.consume_network(local);
    require(send(peer, "next", 4, 0) == 4 && events.wait(1000),
            "Socket readiness was not re-armed");
    events.consume_network(local);
    require(recv(local, data.data(), static_cast<int>(data.size()), 0) == 4,
            "Second receive failed");
    events.consume_network(local);
    require(!events.wait(20), "An idle socket caused a busy wait");
    // A full local send buffer must sleep until the peer drains it. No extra
    // thread or real Hyper-V endpoint is required for this backpressure check.
    int small_buffer = 4096;
    require(setsockopt(local, SOL_SOCKET, SO_SNDBUF,
                      reinterpret_cast<const char*>(&small_buffer), sizeof(small_buffer)) == 0,
            "Fixture buffer configuration failed");
    std::array<char, 65536> bulk{};
    std::size_t written = 0;
    bool blocked = false;
    for (int i = 0; i < 128; ++i) {
      const auto count = send(local, bulk.data(), static_cast<int>(bulk.size()), 0);
      if (count == SOCKET_ERROR) {
        require(WSAGetLastError() == WSAEWOULDBLOCK, "Fixture send failed");
        blocked = true;
        break;
      }
      require(count > 0, "Fixture send did not progress");
      written += static_cast<std::size_t>(count);
    }
    require(blocked, "Fixture did not reach bounded socket backpressure");
    events.consume_network(local);
    u_long nonblocking = 1;
    require(ioctlsocket(peer, FIONBIO, &nonblocking) == 0, "Fixture peer could not be bounded");
    std::size_t drained = 0;
    auto deadline = std::chrono::steady_clock::now() + 3s;
    while (drained < written && std::chrono::steady_clock::now() < deadline) {
      WSAPOLLFD readable{peer, POLLRDNORM, 0};
      require(WSAPoll(&readable, 1, 100) >= 0, "Fixture drain poll failed");
      const auto count = recv(peer, bulk.data(), static_cast<int>(bulk.size()), 0);
      if (count > 0) drained += static_cast<std::size_t>(count);
      else require(count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK,
                   "Fixture drain failed");
    }
    require(drained == written, "Fixture drain timed out");
    require(events.wait(1000), "Writable socket did not wake after backpressure");
    events.consume_network(local);
    require(!events.wait(20), "Writable readiness remained permanently signaled");
    peer.close();
    require(events.wait(1000), "Socket closure did not wake the relay");
    events.consume_network(local);
    require(recv(local, data.data(), static_cast<int>(data.size()), 0) == 0,
            "Graceful socket closure was not observable");
    std::cout << "Native completion, lost-wakeup, idle-bound, socket-read, backpressure and close checks passed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
