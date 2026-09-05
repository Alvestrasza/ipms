#include "ipms/agent/native_console_guard.hpp"
#include "ipms/agent/native_identity_worker.hpp"

#include <iostream>
#include <stdexcept>
#include <vector>
#include <future>
#include <thread>

using namespace std::chrono_literals;
using ipms::agent::native_console_lease;
using ipms::agent::native_preconnection_guard;
constexpr std::string_view vm = "12345678-90ab-cdef-1234-567890abcdef";
constexpr std::string_view generation = "22222222-3333-4444-5555-666666666666";

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

std::vector<std::uint8_t> pdu(std::string pcb) {
  std::vector<std::uint8_t> bytes(18, 0);
  bytes[8] = 2;
  bytes[16] = static_cast<std::uint8_t>(pcb.size() + 1);
  for (char c : pcb) { bytes.push_back(static_cast<std::uint8_t>(c)); bytes.push_back(0); }
  bytes.push_back(0); bytes.push_back(0);
  bytes[0] = static_cast<std::uint8_t>(bytes.size());
  return bytes;
}

void preconnection_contract() {
  for (auto name : {std::string(vm), std::string(vm) + ";EnhancedMode=0",
                    std::string("12345678-90AB-CDEF-1234-567890ABCDEF")}) {
    const auto bytes = pdu(name);
    for (std::size_t split = 0; split < bytes.size(); ++split) {
      native_preconnection_guard guard(vm);
      auto first = guard.append(std::span(bytes).first(split));
      require(first.state == native_preconnection_guard::status::pending,
              "Partial PDU was forwarded");
      auto rest = guard.append(std::span(bytes).subspan(split));
      require(rest.state == native_preconnection_guard::status::accepted &&
              guard.packet().size() == bytes.size(), "Valid fragmented PDU rejected");
      require(guard.append(bytes).state == native_preconnection_guard::status::rejected,
              "One-shot PDU gate accepted replay");
    }
  }
  auto joined = pdu(std::string(vm));
  const auto size = joined.size();
  joined.insert(joined.end(), {0x16, 0x03, 0x03, 0x00});
  native_preconnection_guard guard(vm);
  require(guard.append(joined).consumed == size, "PDU gate consumed following TLS bytes");
  for (const auto text : {std::string(generation), std::string(vm) + ";EnhancedMode=1",
                         std::string(vm) + ";EnhancedMode=0;extra=1", "{" + std::string(vm) + "}"}) {
    native_preconnection_guard invalid(vm);
    require(invalid.append(pdu(text)).state == native_preconnection_guard::status::rejected,
            "Wrong VM or non-basic mode accepted");
  }
  for (std::size_t offset : {0u, 4u, 8u, 12u, 16u, 19u, 90u}) {
    auto invalid_bytes = pdu(std::string(vm));
    invalid_bytes[offset] = 255;
    native_preconnection_guard invalid(vm);
    require(invalid.append(invalid_bytes).state == native_preconnection_guard::status::rejected,
            "Malformed preconnection field accepted");
  }
  auto overflow = pdu(std::string(vm));
  overflow[1] = 255;
  native_preconnection_guard excessive(vm);
  require(excessive.append(overflow).state == native_preconnection_guard::status::rejected,
          "Oversized preconnection allocation accepted");
}

void lease_contract() {
  const std::string valid = "{\"type\":\"lease\",\"seconds\":15,\"stream_generation\":\"" +
      std::string(generation) + "\"}";
  const auto start = native_console_lease::clock::time_point{};
  native_console_lease lease(std::string(generation), start);
  require(!lease.authorized(start), "Binary stream allowed before first lease");
  require(lease.refresh(valid, start + 1s) && lease.authorized(start + 15s),
          "Valid lease did not authorize bounded interval");
  require(!lease.authorized(start + 16s), "Expired lease stayed authorized");
  require(!lease.refresh(valid, start + 16s), "Expired stream was revived");
  for (auto value : {"0", "16", "99999999999", "-1", "01", "1.5", "\"15\""}) {
    auto invalid = valid;
    invalid.replace(invalid.find("15"), 2, value);
    native_console_lease isolated(std::string(generation), start);
    require(!isolated.refresh(invalid, start), "Invalid lease duration accepted");
  }
  for (const auto invalid : {
      valid + "junk", valid.substr(0, valid.size() - 1) + ",\"extra\":1}",
      std::string("{\"type\":\"lease\",\"type\":\"lease\",\"seconds\":15}"),
      std::string("{\"type\":\"lease\",\"seconds\":15,\"stream_generation\":\"") + std::string(vm) + "\"}"}) {
    native_console_lease isolated(std::string(generation), start);
    require(!isolated.refresh(invalid, start), "Malformed/replayed-generation lease accepted");
  }
  native_console_lease backwards(std::string(generation), start);
  require(backwards.refresh(valid, start + 2s) && !backwards.refresh(valid, start + 1s),
          "Non-monotonic lease time accepted");
}

void message_bounds() {
  using message = ipms::agent::native_console_message;
  std::vector<std::uint8_t> full(65'536, 1);
  message valid;
  require(valid.append(std::span(full).first(65'535), false, false) == message::status::pending,
          "Binary fragment did not remain pending");
  require(valid.append(std::span(full).last(1), false, true) == message::status::complete &&
          valid.bytes().size() == 65'536, "Maximum-sized binary message rejected");
  require(valid.append({}, false, true) == message::status::rejected,
          "Completed message was reused without consuming it");
  message excessive;
  require(excessive.append(full, false, false) == message::status::pending &&
          excessive.append(std::span(full).first(1), false, true) == message::status::rejected &&
          excessive.bytes().size() == 65'536, "Fragmentation bypassed the binary message limit");
  message control;
  require(control.append(std::span(full).first(257), true, true) == message::status::rejected &&
          control.bytes().empty(), "Oversized lease message was buffered");
  message mixed;
  require(mixed.append(std::span(full).first(300), false, false) == message::status::pending &&
          mixed.append({}, true, true) == message::status::rejected,
          "Fragment type switch bypassed the control-message limit");
}

void metadata_cannot_block_socket_deadlines() {
  auto entered = std::make_shared<std::promise<void>>();
  auto completed = std::make_shared<std::promise<void>>();
  std::promise<void> released;
  auto entry = entered->get_future();
  auto release = released.get_future().share();
  auto completion = completed->get_future();
  ipms::agent::native_identity_worker worker;
  const auto ticket = worker.submit([entered, completed, release](const auto& cancelled) {
    entered->set_value();
    release.wait();
    const bool result = !cancelled();
    completed->set_value();
    return result;
  });
  require(entry.wait_for(1s) == std::future_status::ready, "Metadata worker did not begin");
  const auto now = native_console_lease::clock::now();
  native_console_lease lease(std::string(generation), now);
  require(!worker.fresh(ticket, now) && !lease.live(now + 15s),
          "Blocked metadata prevented the independent lease from expiring");
  const auto before_stop = native_console_lease::clock::now();
  worker.stop();
  const bool bounded = native_console_lease::clock::now() - before_stop < 1s;
  released.set_value();
  const bool finished = completion.wait_for(1s) == std::future_status::ready;
  require(bounded && finished, "Worker cancellation waited for blocked provider metadata");
  require(!worker.fresh(ticket, native_console_lease::clock::now()),
          "Stopped metadata worker authorized a console");
}

void metadata_results_are_generation_bound() {
  auto old_entered = std::make_shared<std::promise<void>>();
  auto new_entered = std::make_shared<std::promise<void>>();
  std::promise<void> old_release, new_release;
  auto old_entry = old_entered->get_future();
  auto old_wait = old_release.get_future().share();
  auto new_entry = new_entered->get_future();
  auto new_wait = new_release.get_future().share();
  ipms::agent::native_identity_worker worker;
  const auto old_ticket = worker.submit([old_entered, old_wait](const auto&) {
    old_entered->set_value(); old_wait.wait(); return true;
  });
  require(old_entry.wait_for(1s) == std::future_status::ready, "First metadata request did not begin");
  auto superseded_runs = std::make_shared<std::atomic<unsigned>>(0);
  for (int index = 0; index < 100; ++index) {
    worker.submit([superseded_runs](const auto&) { ++*superseded_runs; return true; });
  }
  const auto ticket = worker.submit([new_entered, new_wait](const auto&) {
    new_entered->set_value(); new_wait.wait(); return true;
  });
  old_release.set_value();
  require(new_entry.wait_for(1s) == std::future_status::ready, "Replacement metadata request did not begin");
  const auto now = native_console_lease::clock::now();
  const bool rejected = !worker.fresh(old_ticket, now) && !worker.fresh(ticket, now);
  new_release.set_value();
  const auto until = native_console_lease::clock::now() + 1s;
  while (!worker.fresh(ticket, native_console_lease::clock::now()) &&
         native_console_lease::clock::now() < until) std::this_thread::yield();
  require(rejected && superseded_runs->load() == 0 &&
          worker.fresh(ticket, native_console_lease::clock::now()),
          "Stale metadata result authorized a replacement console");
  require(!worker.fresh(ticket, native_console_lease::clock::now() + 10s),
          "Stale last-success snapshot stayed authorized");
  worker.retire(ticket);
  require(!worker.fresh(ticket, native_console_lease::clock::now()),
          "Retired metadata request remained authorized");
}

int main() {
  try {
    preconnection_contract();
    lease_contract();
    message_bounds();
    metadata_cannot_block_socket_deadlines();
    metadata_results_are_generation_bound();
    std::cout << "Native console preconnection and lease guards passed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
