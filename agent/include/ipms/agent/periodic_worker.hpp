#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <stop_token>
#include <thread>
#include <utility>

namespace ipms::agent {

// A separate bounded operation owns each worker. Slow work elsewhere cannot
// postpone this worker's cadence. Missed periods are skipped, never queued.
class periodic_worker {
 public:
  using cancellation = std::function<bool()>;
  using cycle = std::function<void(const cancellation&)>;

  periodic_worker(std::chrono::milliseconds interval, cycle operation)
      : worker_([this, interval, operation = std::move(operation)](std::stop_token stop) {
          const cancellation cancelled = [stop] { return stop.stop_requested(); };
          const auto cadence = interval > std::chrono::milliseconds::zero()
              ? interval : std::chrono::milliseconds(1);
          auto next = std::chrono::steady_clock::now();
          while (!stop.stop_requested()) {
            try { operation(cancelled); } catch (...) {
              // The owning transport records/returns a bounded result. Failure
              // does not create a busy retry loop or kill another worker.
            }
            next += cadence;
            const auto now = std::chrono::steady_clock::now();
            if (next <= now) next = now + cadence;
            std::unique_lock lock(mutex_);
            condition_.wait_until(lock, stop, next, [] { return false; });
          }
        }) {}

  ~periodic_worker() { stop(); }
  periodic_worker(const periodic_worker&) = delete;
  periodic_worker& operator=(const periodic_worker&) = delete;

  void stop() {
    worker_.request_stop();
    condition_.notify_all();
    if (worker_.joinable()) worker_.join();
  }

 private:
  std::mutex mutex_;
  std::condition_variable_any condition_;
  std::jthread worker_;
};

}  // namespace ipms::agent
