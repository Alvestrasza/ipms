#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace ipms::agent {

// One bounded, read-only validation worker. A provider call may not be
// cancellable; therefore neither socket ownership nor relay callbacks belong
// here. A stopped worker retains only its own state until the call returns.
class native_identity_worker {
 public:
  using clock = std::chrono::steady_clock;
  using cancellation = std::function<bool()>;
  using validation = std::function<bool(const cancellation&)>;

  native_identity_worker() : state_(std::make_shared<state>()), thread_([shared = state_] {
    std::uint64_t seen = 0;
    while (!shared->stopped.load()) {
      validation operation;
      std::uint64_t generation = 0;
      {
        std::unique_lock lock(shared->mutex);
        shared->condition.wait_for(lock, std::chrono::seconds(5), [&] {
          return shared->stopped.load() || shared->generation.load() != seen;
        });
        if (shared->stopped.load()) break;
        generation = shared->generation.load();
        seen = generation;
        operation = shared->operation;
      }
      if (!operation) continue;
      const cancellation cancelled = [shared, generation] {
        return shared->stopped.load() || shared->generation.load() != generation;
      };
      const auto observed_at = ticks(clock::now());
      bool succeeded = false;
      try { if (!cancelled()) succeeded = operation(cancelled); } catch (...) {}
      std::lock_guard publish(shared->mutex);
      if (!cancelled()) {
        if (succeeded) {
          // Slow validation must not make old observations look newly fresh.
          shared->last_success.store(observed_at);
          shared->success_generation.store(generation);
          shared->failed_generation.store(0);
        } else shared->failed_generation.store(generation);
      }
    }
    shared->exited.store(true);
    shared->condition.notify_all();
  }) {}

  ~native_identity_worker() { stop(); }
  native_identity_worker(const native_identity_worker&) = delete;
  native_identity_worker& operator=(const native_identity_worker&) = delete;

  std::uint64_t submit(validation operation) {
    std::lock_guard lock(state_->mutex);
    if (state_->stopped.load()) return 0;
    state_->operation = std::move(operation);
    const auto ticket = state_->generation.fetch_add(1) + 1;
    state_->condition.notify_all();
    return ticket;
  }

  void retire(std::uint64_t ticket) {
    std::lock_guard lock(state_->mutex);
    if (state_->generation.load() != ticket) return;
    state_->operation = {};
    state_->generation.fetch_add(1);
    state_->condition.notify_all();
  }

  bool fresh(std::uint64_t ticket, clock::time_point now) const {
    if (ticket == 0 || state_->stopped.load() || state_->generation.load() != ticket ||
        state_->failed_generation.load() == ticket || state_->success_generation.load() != ticket)
      return false;
    return ticks(now) - state_->last_success.load() < 10'000;
  }

  bool failed(std::uint64_t ticket) const {
    return ticket == 0 || state_->stopped.load() || state_->generation.load() != ticket ||
        state_->failed_generation.load() == ticket;
  }

  void stop() {
    state_->stopped.store(true);
    state_->condition.notify_all();
    if (!thread_.joinable()) return;
    // Usually the idle worker exits immediately. A sick COM provider must not
    // delay service/socket shutdown; there is never a replacement worker.
    std::unique_lock lock(state_->mutex);
    state_->condition.wait_for(lock, std::chrono::milliseconds(100), [&] {
      return state_->exited.load();
    });
    lock.unlock();
    if (state_->exited.load()) thread_.join();
    else thread_.detach();
  }

 private:
  static std::int64_t ticks(clock::time_point value) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();
  }
  struct state {
    std::mutex mutex;
    std::condition_variable condition;
    std::atomic<bool> stopped{false}, exited{false};
    std::atomic<std::uint64_t> generation{0}, success_generation{0}, failed_generation{0};
    std::atomic<std::int64_t> last_success{0};
    validation operation;
  };
  std::shared_ptr<state> state_;
  std::thread thread_;
};

}  // namespace ipms::agent
