#include "ipms/agent/console_input_worker.hpp"
#include "ipms/agent/periodic_worker.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>

using namespace std::chrono_literals;
using ipms::agent::console_input_worker;
using ipms::agent::periodic_worker;

namespace {
void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

void heartbeat_progresses_while_other_work_is_blocked() {
  std::promise<void> release_other_work, frame_entered, telemetry_entered, heartbeats_seen;
  auto release = release_other_work.get_future().share();
  auto frame_ready = frame_entered.get_future();
  auto telemetry_ready = telemetry_entered.get_future();
  auto observed = heartbeats_seen.get_future();
  std::atomic<unsigned> beats{0};
  console_input_worker frame([&](const auto&) {
    frame_entered.set_value();
    release.wait();
    return false;
  }, 150ms, 25ms);
  auto telemetry = std::async(std::launch::async, [&] {
    telemetry_entered.set_value();
    release.wait();
  });
  frame.set_active(true);
  frame_ready.wait();
  telemetry_ready.wait();
  periodic_worker heartbeat(10ms, [&](const auto& cancelled) {
    if (!cancelled() && ++beats == 3) heartbeats_seen.set_value();
  });
  const bool progressed = observed.wait_for(1s) == std::future_status::ready;
  heartbeat.stop();
  release_other_work.set_value();
  frame.stop();
  telemetry.get();
  require(progressed, "Blocked telemetry or frame work starved the heartbeat worker");
}

void periodic_stop_interrupts_a_long_idle_interval() {
  std::promise<void> started;
  auto ready = started.get_future();
  std::atomic<unsigned> runs{0};
  periodic_worker worker(10s, [&](const auto&) {
    if (++runs == 1) started.set_value();
  });
  require(ready.wait_for(1s) == std::future_status::ready, "Heartbeat did not start immediately");
  const auto before_stop = std::chrono::steady_clock::now();
  worker.stop();
  require(std::chrono::steady_clock::now() - before_stop < 1s,
          "Heartbeat stop waited for the normal ten-second interval");
  require(runs.load() == 1, "Heartbeat executed after stop");
}

void periodic_stop_cancels_an_active_operation() {
  std::promise<void> entered, cancelled_operation;
  auto ready = entered.get_future();
  auto cancelled = cancelled_operation.get_future();
  periodic_worker worker(10s, [&](const periodic_worker::cancellation& stop) {
    entered.set_value();
    while (!stop()) std::this_thread::yield();
    cancelled_operation.set_value();
  });
  require(ready.wait_for(1s) == std::future_status::ready, "Heartbeat operation did not begin");
  worker.stop();
  require(cancelled.wait_for(0ms) == std::future_status::ready,
          "Heartbeat stop failed to cancel and join the active operation");
}

void late_inactive_response_cannot_erase_a_newer_activation() {
  std::promise<void> first_entered, release_old_response, second_entered;
  auto first = first_entered.get_future();
  auto release = release_old_response.get_future();
  auto second = second_entered.get_future();
  std::atomic<unsigned> calls{0};
  console_input_worker worker([&](const auto&) {
    const auto call = ++calls;
    if (call == 1) {
      first_entered.set_value();
      release.wait();
    } else if (call == 2) {
      second_entered.set_value();
    }
    return false;
  });
  worker.set_active(true);
  require(first.wait_for(1s) == std::future_status::ready, "First console poll did not run");
  worker.set_active(true);
  release_old_response.set_value();
  const bool retained = second.wait_for(1s) == std::future_status::ready;
  worker.stop();
  require(retained && calls.load() == 2, "A stale inactive response erased a newer console wake-up");
}

void one_failed_heartbeat_does_not_stop_future_periods() {
  std::promise<void> recovered;
  auto recovery = recovered.get_future();
  std::atomic<unsigned> attempts{0};
  periodic_worker heartbeat(10ms, [&](const auto&) {
    const auto attempt = ++attempts;
    if (attempt == 1) throw std::runtime_error("simulated unavailable transport");
    if (attempt == 2) recovered.set_value();
  });
  const bool continued = recovery.wait_for(1s) == std::future_status::ready;
  heartbeat.stop();
  require(continued && attempts.load() >= 2,
          "One failed heartbeat terminated future heartbeat periods");
}
}  // namespace

int main() {
  try {
    heartbeat_progresses_while_other_work_is_blocked();
    periodic_stop_interrupts_a_long_idle_interval();
    periodic_stop_cancels_an_active_operation();
    late_inactive_response_cannot_erase_a_newer_activation();
    one_failed_heartbeat_does_not_stop_future_periods();
    std::cout << "All five heartbeat and service-worker isolation checks passed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
