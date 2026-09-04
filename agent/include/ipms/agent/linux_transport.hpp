#pragma once

#include <string>

namespace ipms::agent::linux {

struct TransportResult {
  bool succeeded{false};
  std::string message;
};

TransportResult run_inventory_cycle();

}  // namespace ipms::agent::linux
