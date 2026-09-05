#pragma once

#include <functional>
#include <string>

namespace ipms::agent::linux {

struct TransportResult {
  bool succeeded{false};
  std::string message;
};

TransportResult run_inventory_cycle();
TransportResult initialize_transport();
TransportResult run_heartbeat_cycle(const std::function<bool()>& cancelled);

}  // namespace ipms::agent::linux
