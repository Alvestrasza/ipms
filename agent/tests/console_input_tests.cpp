#include "ipms/agent/console_input_dispatcher.hpp"
#include "ipms/agent/console_input_worker.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace std::chrono_literals;
using ipms::agent::console_input_assignment;
using ipms::agent::console_input_dispatcher;
using ipms::agent::console_input_poll_result;
using ipms::agent::console_input_receipt;
using ipms::agent::console_input_worker;
using ipms::agent::windows::hyperv_console_result;

namespace {
void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

console_input_poll_result poll_batch() {
  return {true, console_input_assignment{
      "session-one", "vm-one", "Test VM", {{"event-one", "key", 65, true}}}};
}

hyperv_console_result applied_batch() {
  return {true, "input_applied", {}, 0, 0, {"event-one"}};
}

void acknowledgement_loss_does_not_replay() {
  console_input_dispatcher dispatcher;
  unsigned polls = 0, applications = 0, receipts = 0;
  const auto poll = [&] { ++polls; return poll_batch(); };
  const auto apply = [&](const auto&, const auto&) { ++applications; return applied_batch(); };
  const auto deliver = [&](const console_input_receipt& receipt) {
    require(receipt.session_id == "session-one" &&
            receipt.acknowledged_ids == std::vector<std::string>{"event-one"},
            "ACK retry changed its session or applied input IDs");
    if (++receipts == 1) throw std::runtime_error("simulated lost ACK response");
    return false;
  };
  try {
    dispatcher.cycle("device-one", [] { return false; }, poll, apply, deliver, [] { return true; });
    throw std::logic_error("Expected the simulated ACK loss");
  } catch (const std::runtime_error&) {}
  require(!dispatcher.cycle("device-one", [] { return false; }, poll, apply, deliver,
                            [] { return true; }), "Closed-session ACK was not honored");
  require(polls == 1 && applications == 1 && receipts == 2,
          "Uncertain input ACK caused another poll or VM input execution");
}

void partial_apply_exception_fails_closed() {
  console_input_dispatcher dispatcher;
  unsigned polls = 0, applications = 0;
  const auto poll = [&] { ++polls; return poll_batch(); };
  const auto apply = [&](const auto&, const auto&) -> hyperv_console_result {
    ++applications;
    throw std::runtime_error("provider failed after an uncertain operation");
  };
  const auto deliver = [](const console_input_receipt& receipt) {
    require(receipt.failure_code == "console_input_failed", "Uncertain input did not fail closed");
    return false;
  };
  try {
    dispatcher.cycle("device-one", [] { return false; }, poll, apply, deliver, [] { return true; });
  } catch (const std::runtime_error&) {}
  dispatcher.cycle("device-one", [] { return false; }, poll, apply, deliver, [] { return true; });
  require(polls == 1 && applications == 1, "Partially applied input batch was replayed");
}

void stale_assignment_and_stop_are_not_applied() {
  console_input_dispatcher dispatcher;
  bool cancelled = false;
  unsigned applications = 0, receipts = 0;
  const auto apply = [&](const auto&, const auto&) { ++applications; return applied_batch(); };
  const auto deliver = [&](const auto&) { ++receipts; return true; };
  dispatcher.cycle("device-one", [&] { return cancelled; }, poll_batch, apply, deliver,
                   [] { return false; });
  dispatcher.cycle("device-one", [&] { return cancelled; }, [&] {
    cancelled = true;
    return poll_batch();
  }, apply, deliver, [] { return true; });
  require(applications == 0 && receipts == 0, "Stale or cancelled input was applied");
}

void ordered_batch_acknowledges_partial_success() {
  console_input_dispatcher dispatcher;
  auto poll = [] {
    auto value = poll_batch();
    value.assignment->inputs.push_back({"event-two", "key", 65, false});
    return value;
  };
  dispatcher.cycle("device-one", [] { return false; }, poll,
      [](const console_input_assignment& assignment, const auto&) {
        require(assignment.inputs[0].is_down && !assignment.inputs[1].is_down,
                "The ordered key press/release batch changed order");
        return hyperv_console_result{false, "provider_failed", {}, 0, 0, {"event-one"}};
      },
      [](const console_input_receipt& receipt) {
        require(receipt.failure_code == "console_input_failed" &&
                receipt.acknowledged_ids == std::vector<std::string>{"event-one"},
                "Partial input completion lost ACKs or failed to close the session");
        return false;
      }, [] { return true; });
}

void frame_work_cannot_block_input_worker() {
  std::promise<void> release_frame, frame_started, input_applied;
  auto release = release_frame.get_future();
  auto started = frame_started.get_future();
  auto applied = input_applied.get_future();
  auto frame = std::async(std::launch::async, [&] {
    frame_started.set_value();
    release.wait();
  });
  started.wait();
  std::atomic<bool> completed{false};
  console_input_worker worker([&](const auto&) {
    if (!completed.exchange(true)) input_applied.set_value();
    return true;
  });
  worker.set_active(true);
  const bool independent = applied.wait_for(1s) == std::future_status::ready;
  worker.stop();
  release_frame.set_value();
  frame.get();
  require(independent, "A blocked frame capture prevented independent input processing");
}

void worker_stop_cancels_an_outstanding_poll() {
  std::promise<void> entered, left;
  auto entered_future = entered.get_future();
  auto left_future = left.get_future();
  console_input_worker worker([&](const console_input_worker::cancellation& cancelled) {
    entered.set_value();
    while (!cancelled()) std::this_thread::yield();
    left.set_value();
    return false;
  });
  worker.set_active(true);
  require(entered_future.wait_for(1s) == std::future_status::ready, "Input worker failed to start");
  worker.stop();
  require(left_future.wait_for(0ms) == std::future_status::ready,
          "Input worker stop failed to cancel and join the active callback");
}

void receipt_survives_worker_restart() {
  console_input_dispatcher dispatcher;
  unsigned applications = 0;
  std::promise<void> attempted;
  auto attempted_future = attempted.get_future();
  {
    console_input_worker worker([&](const auto& cancelled) {
      return dispatcher.cycle("device-one", cancelled, poll_batch,
          [&](const auto&, const auto&) { ++applications; return applied_batch(); },
          [&](const auto&) -> bool {
            attempted.set_value();
            throw std::runtime_error("lost ACK");
          }, [] { return true; });
    });
    worker.set_active(true);
    require(attempted_future.wait_for(1s) == std::future_status::ready, "Initial ACK was not attempted");
    worker.stop();
  }
  std::promise<void> retried;
  auto retried_future = retried.get_future();
  {
    console_input_worker worker([&](const auto& cancelled) {
      return dispatcher.cycle("device-one", cancelled,
          []() -> console_input_poll_result { throw std::runtime_error("Unexpected new poll"); },
          [&](const auto&, const auto&) { ++applications; return applied_batch(); },
          [&](const console_input_receipt& receipt) {
            require(receipt.acknowledged_ids == std::vector<std::string>{"event-one"},
                    "Worker restart forgot applied input receipt");
            retried.set_value();
            return false;
          }, [] { return true; });
    });
    worker.set_active(true);
    require(retried_future.wait_for(1s) == std::future_status::ready, "Restart did not retry the receipt");
    worker.stop();
  }
  require(applications == 1, "Worker restart replayed an already applied event");
}

void no_active_session_idles_until_reenabled() {
  std::promise<void> first_poll, second_poll;
  auto first = first_poll.get_future();
  auto second = second_poll.get_future();
  std::atomic<unsigned> polls{0};
  console_input_worker worker([&](const auto&) {
    const auto count = ++polls;
    if (count == 1) first_poll.set_value();
    if (count == 2) second_poll.set_value();
    return false;
  });
  worker.set_active(true);
  require(first.wait_for(1s) == std::future_status::ready, "Initial input poll did not run");
  require(second.wait_for(100ms) == std::future_status::timeout && polls.load() == 1,
          "Inactive input session kept polling while frame work was blocked");
  worker.set_active(true);
  require(second.wait_for(1s) == std::future_status::ready,
          "A newly activated console did not wake the idle input worker");
  worker.stop();
  require(polls.load() == 2, "Input worker kept polling after its second inactive response");
}
}  // namespace

int main() {
  try {
    acknowledgement_loss_does_not_replay();
    partial_apply_exception_fails_closed();
    stale_assignment_and_stop_are_not_applied();
    ordered_batch_acknowledges_partial_success();
    frame_work_cannot_block_input_worker();
    worker_stop_cancels_an_outstanding_poll();
    receipt_survives_worker_restart();
    no_active_session_idles_until_reenabled();
    std::cout << "All eight console input isolation and retry checks passed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
