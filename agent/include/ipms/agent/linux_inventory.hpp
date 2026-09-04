#pragma once

#include <string>
#include <vector>

namespace ipms::agent::linux {

std::string collect_linux_inventory_json();
std::vector<std::string> collect_linux_software_inventory_pages();

}  // namespace ipms::agent::linux
