#include "ipms/agent/linux_transport.hpp"
#include "ipms/agent/periodic_worker.hpp"

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
  // A disconnected TLS peer must fail its request, not terminate the service.
  std::signal(SIGPIPE, SIG_IGN);
  const auto initialized = initialize_transport();
  if (!initialized.succeeded) {
    std::cerr << initialized.message << '\n';
    return 1;
  }
  // Liveness remains independent of slow inventory collection and uploads.
  // Only the main thread may enroll; this worker uses an existing identity.
  ipms::agent::periodic_worker heartbeat(std::chrono::seconds(10), [](const auto& cancelled) {
    const auto stopping = [&cancelled] { return stop_requested.load() || cancelled(); };
    const auto result = run_heartbeat_cycle(stopping);
    if (!result.succeeded && !stopping()) std::cerr << result.message << '\n';
  });
  while (!stop_requested) {
    const auto result = run_inventory_cycle();
    if (!result.succeeded) std::cerr << result.message << '\n';
    for (int elapsed = 0; elapsed < 300 && !stop_requested; ++elapsed) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }
  heartbeat.stop();
  return 0;
}

}  // namespace ipms::agent::linux
