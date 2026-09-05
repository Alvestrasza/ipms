#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <stop_token>
#include <thread>
#include <utility>

namespace ipms::agent {

// Separate from frame capture by construction. The worker is idle without an
// active console and its callback owns all COM/HTTP objects on this thread.
class console_input_worker {
 public:
  using cancellation = std::function<bool()>;
  using cycle = std::function<bool(const cancellation&)>;

  explicit console_input_worker(cycle operation)
      : worker_([this, operation = std::move(operation)](std::stop_token stop) {
          const cancellation cancelled = [this, stop] {
            return stop.stop_requested() || !enabled_.load();
          };
          while (!stop.stop_requested()) {
            {
              std::unique_lock lock(mutex_);
              condition_.wait(lock, stop, [this] { return enabled_.load(); });
            }
            if (stop.stop_requested()) break;
            try {
              if (!operation(cancelled)) set_active(false);
            } catch (...) {
              // The dispatcher retains its pending receipt on failure. Back off
              // briefly without hiding service-stop or session-close requests.
              std::unique_lock lock(mutex_);
              condition_.wait_for(lock, stop, std::chrono::milliseconds(250),
                                  [this] { return !enabled_.load(); });
            }
            std::unique_lock lock(mutex_);
            condition_.wait_for(lock, stop, std::chrono::milliseconds(10),
                                [this] { return !enabled_.load(); });
          }
        }) {}

  ~console_input_worker() { stop(); }
  console_input_worker(const console_input_worker&) = delete;
  console_input_worker& operator=(const console_input_worker&) = delete;

  void set_active(bool value) {
    {
      std::lock_guard lock(mutex_);
      enabled_.store(value);
    }
    condition_.notify_all();
  }

  void stop() {
    worker_.request_stop();
    condition_.notify_all();
    if (worker_.joinable()) worker_.join();
  }

 private:
  std::atomic<bool> enabled_{false};
  std::mutex mutex_;
  std::condition_variable_any condition_;
  std::jthread worker_;
};

}  // namespace ipms::agent
