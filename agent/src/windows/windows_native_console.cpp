#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#include "ipms/agent/windows_native_console.hpp"
#include "ipms/agent/native_console_guard.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
using clock_type = std::chrono::steady_clock;
using namespace std::chrono_literals;
constexpr std::size_t maximum_message = 65'536;

struct internet_closer {
  void operator()(void* value) const { if (value) WinHttpCloseHandle(value); }
};
using internet_handle = std::unique_ptr<void, internet_closer>;

// Async buffers must outlive cancellation: each handle's callback context owns
// this state until HANDLE_CLOSING, the documented last WinHTTP notification.
struct asynchronous_state {
  std::mutex mutex;
  bool request_sent{false}, headers{false}, read_ready{false}, write_ready{true};
  bool error{false};
  DWORD read_size{0};
  DWORD expected_write_size{0};
  WINHTTP_WEB_SOCKET_BUFFER_TYPE read_type{};
  std::array<std::uint8_t, maximum_message> read_buffer{};
  std::array<std::uint8_t, maximum_message> write_buffer{};
};
struct callback_context { std::shared_ptr<asynchronous_state> state; };

void CALLBACK status_callback(HINTERNET, DWORD_PTR raw, DWORD notification,
                              void* information, DWORD length) noexcept {
  if (!raw) return;
  auto* context = reinterpret_cast<callback_context*>(raw);
  if (notification == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
    delete context;
    return;
  }
  const auto state = context->state;
  std::lock_guard lock(state->mutex);
  if (notification == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR ||
      notification == WINHTTP_CALLBACK_STATUS_SECURE_FAILURE) state->error = true;
  else if (notification == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE) state->request_sent = true;
  else if (notification == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE) state->headers = true;
  else if (notification == WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE) {
    if (!information || length != sizeof(WINHTTP_WEB_SOCKET_STATUS) ||
        static_cast<WINHTTP_WEB_SOCKET_STATUS*>(information)->dwBytesTransferred != state->expected_write_size)
      state->error = true;
    state->write_ready = true;
  }
  else if (notification == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) {
    if (!information || length != sizeof(WINHTTP_WEB_SOCKET_STATUS)) {
      state->error = true;
      return;
    }
    const auto* status = static_cast<WINHTTP_WEB_SOCKET_STATUS*>(information);
    state->read_size = status->dwBytesTransferred;
    state->read_type = status->eBufferType;
    state->read_ready = true;
    if (state->read_size > state->read_buffer.size()) state->error = true;
  }
}

struct winsock_scope {
  winsock_scope() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
      throw std::runtime_error("The native console socket runtime is unavailable.");
  }
  ~winsock_scope() { WSACleanup(); }
};
struct socket_scope {
  SOCKET value{INVALID_SOCKET};
  ~socket_scope() {
    if (value != INVALID_SOCKET) { shutdown(value, SD_BOTH); closesocket(value); }
  }
};

void require(bool result, const char* message) {
  if (!result) throw std::runtime_error(message);
}

DWORD_PTR attach_context(HINTERNET handle, const std::shared_ptr<asynchronous_state>& state) {
  auto context = std::make_unique<callback_context>(callback_context{state});
  auto raw = reinterpret_cast<DWORD_PTR>(context.get());
  require(WinHttpSetOption(handle, WINHTTP_OPTION_CONTEXT_VALUE, &raw, sizeof(raw)) != FALSE,
          "The native console callback context could not be installed.");
  context.release();
  return raw;
}

}  // namespace

namespace ipms::agent::windows {

void relay_native_hyperv_console(
    const std::wstring& gateway, std::uint16_t gateway_port,
    const std::string& session_id, const std::string& stream_generation,
    const std::string& vm_id, PCCERT_CONTEXT certificate,
    const std::function<bool()>& cancelled) {
  // One in-process attachment, including asynchronous cancellation cleanup.
  // Never accumulate orphaned callback buffers during repeated failed connects.
  static std::mutex attachment_mutex;
  static std::weak_ptr<asynchronous_state> preceding_attachment;
  std::unique_lock attachment_lock(attachment_mutex, std::try_to_lock);
  require(attachment_lock.owns_lock() && preceding_attachment.expired(),
          "The previous native console attachment is still closing.");
  require(certificate && native_console_uuid(session_id) && native_console_uuid(stream_generation) &&
          native_console_uuid(vm_id), "The native console assignment is invalid.");
  auto state = std::make_shared<asynchronous_state>();
  preceding_attachment = state;
  native_console_lease lease(stream_generation, clock_type::now());
  const auto check = [&] {
    require(!(cancelled && cancelled()) && lease.live(clock_type::now()),
            "The native console authorization expired or was cancelled.");
    std::lock_guard lock(state->mutex);
    require(!state->error, "The native console authenticated transport failed.");
  };
  check();
  internet_handle session(WinHttpOpen(L"IPMS-Agent/0.2.26", WINHTTP_ACCESS_TYPE_NO_PROXY,
      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC));
  require(session != nullptr, "The native console session could not be created.");
  require(WinHttpSetStatusCallback(session.get(), status_callback,
      WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS | WINHTTP_CALLBACK_FLAG_HANDLES |
      WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0) != WINHTTP_INVALID_STATUS_CALLBACK,
      "The native console callbacks could not be installed.");
  require(WinHttpSetTimeouts(session.get(), 2'000, 2'000, 2'000, 20'000) != FALSE,
          "The native console timeouts could not be configured.");
  DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
  require(WinHttpSetOption(session.get(), WINHTTP_OPTION_SECURE_PROTOCOLS,
                          &protocols, sizeof(protocols)) != FALSE,
          "The native console requires TLS 1.3.");
  internet_handle connection(WinHttpConnect(session.get(), gateway.c_str(), gateway_port, 0));
  require(connection != nullptr, "The native console Gateway is unavailable.");
  internet_handle request(WinHttpOpenRequest(connection.get(), L"GET", L"/v1/hyperv-console-native",
      nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
  require(request != nullptr, "The native console request could not be created.");
  const auto request_context = attach_context(request.get(), state);
  DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  DWORD disabled_features = WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES;
  require(WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect)) &&
          WinHttpSetOption(request.get(), WINHTTP_OPTION_DISABLE_FEATURE,
                           &disabled_features, sizeof(disabled_features)) &&
          WinHttpSetOption(request.get(), WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                           const_cast<CERT_CONTEXT*>(certificate), sizeof(CERT_CONTEXT)) &&
          WinHttpSetOption(request.get(), WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0),
          "The native console security policy could not be configured.");
  const std::wstring headers = L"X-IPMS-Console-Session: " +
      std::wstring(session_id.begin(), session_id.end()) + L"\r\nX-IPMS-Console-Generation: " +
      std::wstring(stream_generation.begin(), stream_generation.end()) + L"\r\n";
  const auto wait_for = [&](bool asynchronous_state::*member) {
    while (true) {
      check();
      { std::lock_guard lock(state->mutex); if (state.get()->*member) return; }
      std::this_thread::sleep_for(10ms);
    }
  };
  require(WinHttpSendRequest(request.get(), headers.c_str(), static_cast<DWORD>(headers.size()),
      WINHTTP_NO_REQUEST_DATA, 0, 0, request_context) != FALSE,
      "The native console upgrade request failed.");
  wait_for(&asynchronous_state::request_sent);
  require(WinHttpReceiveResponse(request.get(), nullptr) != FALSE,
          "The native console upgrade response failed.");
  wait_for(&asynchronous_state::headers);
  DWORD response_status = 0, status_size = sizeof(response_status);
  require(WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
      WINHTTP_HEADER_NAME_BY_INDEX, &response_status, &status_size, WINHTTP_NO_HEADER_INDEX) &&
      response_status == 101, "The native console upgrade was rejected.");
  auto websocket_context = std::make_unique<callback_context>(callback_context{state});
  internet_handle websocket(WinHttpWebSocketCompleteUpgrade(request.get(),
      reinterpret_cast<DWORD_PTR>(websocket_context.get())));
  require(websocket != nullptr, "The native console WebSocket could not be opened.");
  websocket_context.release();
  request.reset();
  winsock_scope winsock;
  socket_scope local;
  native_preconnection_guard preconnection(vm_id);
  bool preconnection_valid = false, connecting = false, read_pending = false;
  bool write_pending = false;
  auto connect_deadline = clock_type::now(), local_write_deadline = connect_deadline;
  auto websocket_write_deadline = connect_deadline;
  const auto preconnection_deadline = clock_type::now() + 10s;
  native_console_message incoming;
  std::vector<std::uint8_t> local_output;
  std::size_t local_offset = 0;
  local_output.reserve(maximum_message + 256);
  const auto start_local = [&] {
    check();
    local.value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(local.value != INVALID_SOCKET, "The local native console socket is unavailable.");
    u_long nonblocking = 1;
    require(ioctlsocket(local.value, FIONBIO, &nonblocking) == 0,
            "The local native console socket could not be bounded.");
    BOOL no_delay = TRUE;
    require(setsockopt(local.value, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&no_delay), sizeof(no_delay)) == 0,
            "The local native console latency policy could not be configured.");
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(2179);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const auto result = connect(local.value, reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    require(result == 0 || WSAGetLastError() == WSAEWOULDBLOCK,
            "The fixed local native console endpoint could not be reached.");
    connecting = result != 0;
    connect_deadline = clock_type::now() + 2s;
  };
  for (;;) {
    check();
    const auto now = clock_type::now();
    require(preconnection_valid || now < preconnection_deadline,
            "The native console preconnection timed out.");
    if (local.value != INVALID_SOCKET) {
      require(lease.authorized(now), "The native console stream has no valid lease.");
      if (connecting) {
        require(now < connect_deadline, "The local native console connection timed out.");
        WSAPOLLFD readiness{local.value, POLLWRNORM, 0};
        const auto polled = WSAPoll(&readiness, 1, 0);
        require(polled >= 0 && !(readiness.revents & (POLLERR | POLLHUP | POLLNVAL)),
                "The local native console connection failed.");
        if (readiness.revents & POLLWRNORM) {
          int error = 0, length = sizeof(error);
          require(getsockopt(local.value, SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&error), &length) == 0 && error == 0,
                  "The local native console connection failed.");
          connecting = false;
          local_write_deadline = now + 2s;
        }
      }
      if (!connecting && local_offset < local_output.size()) {
        require(now < local_write_deadline, "The local native console write stalled.");
        const auto sent = send(local.value,
            reinterpret_cast<const char*>(local_output.data() + local_offset),
            static_cast<int>(local_output.size() - local_offset), 0);
        if (sent > 0) local_offset += static_cast<std::size_t>(sent);
        else require(sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK,
                     "The local native console write failed.");
        if (local_offset == local_output.size()) { local_output.clear(); local_offset = 0; }
      }
    }
    bool read_ready = false, write_ready = false;
    DWORD received = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE buffer_type{};
    {
      std::lock_guard lock(state->mutex);
      read_ready = state->read_ready;
      write_ready = state->write_ready;
      if (read_ready) {
        received = state->read_size;
        buffer_type = state->read_type;
        state->read_ready = false;
      }
    }
    if (write_pending) {
      if (write_ready) write_pending = false;
      else require(now < websocket_write_deadline, "The native console Gateway write stalled.");
    }
    if (read_ready) {
      read_pending = false;
      require(received <= state->read_buffer.size(), "The native console receive exceeds its bound.");
      if (buffer_type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) return;
      const bool text = buffer_type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
                        buffer_type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE;
      const bool binary = buffer_type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE ||
                          buffer_type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE;
      require(text || binary,
              "The native console message type is invalid.");
      const bool final = buffer_type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
                         buffer_type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
      const auto assembled = incoming.append(std::span(state->read_buffer).first(received), text, final);
      require(assembled != native_console_message::status::rejected,
              "The native console message exceeds its fixed contract.");
      if (assembled == native_console_message::status::complete) {
        const auto message = incoming.bytes();
        if (text) {
          require(lease.refresh(std::string_view(reinterpret_cast<const char*>(message.data()),
                                                message.size()), now),
                  "The native console lease control is invalid.");
        } else {
          require(lease.authorized(now), "The native console stream preceded its lease.");
          std::size_t consumed = 0;
          if (!preconnection_valid) {
            const auto result = preconnection.append(message);
            require(result.state != native_preconnection_guard::status::rejected,
                    "The native console preconnection does not match the assigned VM.");
            consumed = result.consumed;
            if (result.state == native_preconnection_guard::status::accepted) {
              preconnection_valid = true;
              const auto packet = preconnection.packet();
              local_output.insert(local_output.end(), packet.begin(), packet.end());
              start_local();
            }
          }
          if (preconnection_valid) {
            require(local_output.size() + message.size() - consumed <= maximum_message + 256,
                    "The native console local write buffer exceeds its bound.");
            local_output.insert(local_output.end(), message.begin() + consumed, message.end());
            local_write_deadline = now + 2s;
          }
        }
        incoming.reset();
      }
    }
    if (!read_pending && local_output.empty()) {
      const DWORD started = WinHttpWebSocketReceive(websocket.get(), state->read_buffer.data(),
          static_cast<DWORD>(state->read_buffer.size()), nullptr, nullptr);
      require(started == NO_ERROR, "The native console receive could not be started.");
      read_pending = true;
    }
    if (local.value != INVALID_SOCKET && !connecting && !write_pending) {
      const auto count = recv(local.value, reinterpret_cast<char*>(state->write_buffer.data()),
                              static_cast<int>(state->write_buffer.size()), 0);
      if (count == 0) return;
      if (count > 0) {
        {
          std::lock_guard lock(state->mutex);
          state->write_ready = false;
          state->expected_write_size = static_cast<DWORD>(count);
        }
        const DWORD started = WinHttpWebSocketSend(websocket.get(),
            WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, state->write_buffer.data(),
            static_cast<DWORD>(count));
        require(started == NO_ERROR, "The native console send could not be started.");
        write_pending = true;
        websocket_write_deadline = now + 2s;
      } else require(WSAGetLastError() == WSAEWOULDBLOCK,
                     "The local native console receive failed.");
    }
    std::this_thread::sleep_for(10ms);
  }
}

}  // namespace ipms::agent::windows
