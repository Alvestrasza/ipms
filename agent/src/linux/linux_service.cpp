#include "ipms/agent/linux_transport.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

namespace {
std::atomic_bool stop_requested{false};
void stop(int) { stop_requested = true; }
}

namespace ipms::agent::linux {

int run_linux_service() {
  std::signal(SIGTERM, stop);
  std::signal(SIGINT, stop);
  while (!stop_requested) {
    const auto result = run_inventory_cycle();
    if (!result.succeeded) std::cerr << result.message << '\n';
    for (int elapsed = 0; elapsed < 300 && !stop_requested; ++elapsed) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }
  return 0;
}

}  // namespace ipms::agent::linux
