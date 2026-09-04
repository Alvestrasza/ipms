#include "ipms/agent/linux_inventory.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <mntent.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
constexpr std::size_t k_max_packages = 4'096;
constexpr std::size_t k_max_page_items = 128;
constexpr std::size_t k_max_page_item_bytes = 48 * 1024;

std::string trim(std::string value) {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
  return value;
}

std::string bounded(std::string value, std::size_t limit) {
  value = trim(std::move(value));
  if (value.size() > limit) value.resize(limit);
  return value;
}

std::string json_escape(std::string_view value) {
  std::ostringstream output;
  for (const unsigned char character : value) {
    switch (character) {
      case '"': output << "\\\""; break;
      case '\\': output << "\\\\"; break;
      case '\b': output << "\\b"; break;
      case '\f': output << "\\f"; break;
      case '\n': output << "\\n"; break;
      case '\r': output << "\\r"; break;
      case '\t': output << "\\t"; break;
      default:
        if (character < 0x20) {
          output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                 << static_cast<unsigned>(character) << std::dec;
        } else {
          output << static_cast<char>(character);
        }
    }
  }
  return output.str();
}

std::string read_text(const char* path, std::size_t maximum = 16'384) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return {};
  std::string value;
  value.resize(maximum);
  input.read(value.data(), static_cast<std::streamsize>(value.size()));
  value.resize(static_cast<std::size_t>(input.gcount()));
  return trim(std::move(value));
}

std::map<std::string, std::string> os_release() {
  std::map<std::string, std::string> values;
  std::istringstream input(read_text("/etc/os-release"));
  for (std::string line; std::getline(input, line);) {
    const auto separator = line.find('=');
    if (separator == std::string::npos) continue;
    auto value = trim(line.substr(separator + 1));
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
      value = value.substr(1, value.size() - 2);
    }
    values.emplace(line.substr(0, separator), bounded(value, 255));
  }
  return values;
}

std::string hostname_value() {
  std::array<char, 256> value{};
  return gethostname(value.data(), value.size() - 1) == 0 ? bounded(value.data(), 255) : "linux-system";
}

std::string fqdn_value(const std::string& hostname) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  addrinfo* result = nullptr;
  std::string fqdn = hostname;
  if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) == 0 && result) {
    if (result->ai_canonname && *result->ai_canonname) fqdn = bounded(result->ai_canonname, 255);
    freeaddrinfo(result);
  }
  return fqdn;
}

std::uint64_t memory_total_bytes() {
  std::istringstream input(read_text("/proc/meminfo"));
  for (std::string key; input >> key;) {
    std::uint64_t value = 0;
    std::string unit;
    input >> value >> unit;
    if (key == "MemTotal:") return value * 1024;
  }
  return 1;
}

std::string machine_type(const std::string& manufacturer, const std::string& model) {
  std::string text = manufacturer + " " + model + " " + read_text("/sys/hypervisor/type", 128);
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
  for (const auto marker : {"virtual", "vmware", "kvm", "xen", "qemu", "hyper-v", "parallels"}) {
    if (text.find(marker) != std::string::npos) return "virtual";
  }
  return "physical";
}

unsigned prefix_length(const sockaddr* mask) {
  if (!mask) return 0;
  const auto* bytes = mask->sa_family == AF_INET
      ? reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in*>(mask)->sin_addr)
      : reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in6*>(mask)->sin6_addr);
  const std::size_t length = mask->sa_family == AF_INET ? 4 : 16;
  unsigned bits = 0;
  for (std::size_t index = 0; index < length; ++index) {
    for (unsigned bit = 0; bit < 8; ++bit) bits += (bytes[index] >> (7 - bit)) & 1U;
  }
  return bits;
}

std::string network_json() {
  struct interface_record {
    bool up{false};
    std::string mac;
    std::vector<std::pair<std::string, unsigned>> addresses;
  };
  std::map<std::string, interface_record> records;
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) return "[]";
  for (auto* item = list; item; item = item->ifa_next) {
    if (!item->ifa_name || !item->ifa_addr) continue;
    auto& record = records[item->ifa_name];
    record.up = (item->ifa_flags & IFF_UP) != 0;
    if (item->ifa_addr->sa_family == AF_PACKET) {
      const auto* link = reinterpret_cast<const sockaddr_ll*>(item->ifa_addr);
      if (link->sll_halen == 6) {
        std::ostringstream mac;
        for (unsigned index = 0; index < 6; ++index) {
          if (index) mac << ':';
          mac << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<unsigned>(link->sll_addr[index]);
        }
        record.mac = mac.str();
      }
    } else if (item->ifa_addr->sa_family == AF_INET || item->ifa_addr->sa_family == AF_INET6) {
      char address[INET6_ADDRSTRLEN]{};
      const void* source = item->ifa_addr->sa_family == AF_INET
          ? static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(item->ifa_addr)->sin_addr)
          : static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(item->ifa_addr)->sin6_addr);
      if (inet_ntop(item->ifa_addr->sa_family, source, address, sizeof(address))) {
        record.addresses.emplace_back(address, prefix_length(item->ifa_netmask));
      }
    }
  }
  freeifaddrs(list);
  std::ostringstream json;
  json << '[';
  std::size_t emitted = 0;
  for (const auto& [name, record] : records) {
    if (emitted >= 64) break;
    if (emitted++) json << ',';
    json << "{\"interface_id\":\"" << json_escape(bounded(name, 128))
         << "\",\"name\":\"" << json_escape(bounded(name, 255))
         << "\",\"description\":\"Linux network interface\",\"mac_address\":\""
         << json_escape(record.mac) << "\",\"status\":\"" << (record.up ? "up" : "down")
         << "\",\"transmit_link_speed_bps\":0,\"receive_link_speed_bps\":0,"
         << "\"dhcp_enabled\":false,\"dns_suffix\":\"\",\"addresses\":[";
    for (std::size_t index = 0; index < record.addresses.size() && index < 64; ++index) {
      if (index) json << ',';
      json << "{\"address\":\"" << json_escape(record.addresses[index].first)
           << "\",\"prefix_length\":" << record.addresses[index].second << "}";
    }
    json << "],\"gateways\":[],\"dns_servers\":[]}";
  }
  json << ']';
  return json.str();
}

std::string volumes_json() {
  FILE* mounts = setmntent("/proc/self/mounts", "r");
  if (!mounts) return "[]";
  std::ostringstream json;
  json << '[';
  std::set<std::string> seen;
  const std::set<std::string> excluded_filesystems = {
      "autofs", "cgroup", "cgroup2", "debugfs", "devpts", "devtmpfs",
      "efivarfs", "fusectl", "hugetlbfs", "mqueue", "overlay", "proc",
      "pstore", "securityfs", "squashfs", "sysfs", "tmpfs", "tracefs",
  };
  std::size_t emitted = 0;
  while (const auto* entry = getmntent(mounts)) {
    if (emitted >= 64 || !entry->mnt_fsname || entry->mnt_fsname[0] != '/' ||
        !entry->mnt_dir || !entry->mnt_type ||
        excluded_filesystems.contains(entry->mnt_type)) {
      continue;
    }
    if (!seen.emplace(entry->mnt_dir).second) continue;
    struct statvfs status {};
    if (statvfs(entry->mnt_dir, &status) != 0) continue;
    const std::uint64_t total = static_cast<std::uint64_t>(status.f_blocks) * status.f_frsize;
    const std::uint64_t free = static_cast<std::uint64_t>(status.f_bavail) * status.f_frsize;
    if (total == 0 || free > total) continue;
    if (emitted++) json << ',';
    const auto name = bounded(entry->mnt_dir, 16);
    const auto used_percent = ((total - free) * 100 + total / 2) / total;
    json << "{\"name\":\"" << json_escape(name) << "\",\"label\":\"\","
         << "\"filesystem\":\"" << json_escape(bounded(entry->mnt_type ? entry->mnt_type : "", 64))
         << "\",\"total_bytes\":" << total << ",\"free_bytes\":" << free
         << ",\"used_percent\":" << used_percent << "}";
  }
  endmntent(mounts);
  json << ']';
  return json.str();
}

struct apt_scan_result {
  bool succeeded{false};
  std::map<std::string, std::string> upgrades;
};

apt_scan_result apt_upgrades() {
  apt_scan_result result;
  int output_pipe[2]{};
  if (pipe(output_pipe) != 0) return result;
  const pid_t child = fork();
  if (child == 0) {
    dup2(output_pipe[1], STDOUT_FILENO);
    const int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) dup2(devnull, STDERR_FILENO);
    close(output_pipe[0]);
    close(output_pipe[1]);
    execl("/usr/bin/apt-get", "apt-get", "-s", "-o", "Debug::NoLocking=1",
          "-o", "APT::Get::Show-Upgraded=true", "upgrade", static_cast<char*>(nullptr));
    _exit(127);
  }
  close(output_pipe[1]);
  if (child < 0) {
    close(output_pipe[0]);
    return result;
  }
  fcntl(output_pipe[0], F_SETFL, fcntl(output_pipe[0], F_GETFL) | O_NONBLOCK);
  std::string output;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
  int child_status = 0;
  while (std::chrono::steady_clock::now() < deadline) {
    std::array<char, 8'192> buffer{};
    const auto read_count = read(output_pipe[0], buffer.data(), buffer.size());
    if (read_count > 0 && output.size() < 2 * 1024 * 1024) {
      output.append(buffer.data(), static_cast<std::size_t>(read_count));
    }
    if (waitpid(child, &child_status, WNOHANG) == child) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (waitpid(child, &child_status, WNOHANG) == 0) {
    kill(child, SIGKILL);
    waitpid(child, &child_status, 0);
  }
  close(output_pipe[0]);
  if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) return result;
  std::istringstream lines(output);
  for (std::string line; std::getline(lines, line);) {
    if (line.rfind("Inst ", 0) != 0) continue;
    const auto name_end = line.find(' ', 5);
    const auto version_open = line.find('(', name_end);
    const auto version_end = line.find(' ', version_open + 1);
    if (name_end == std::string::npos || version_open == std::string::npos || version_end == std::string::npos) continue;
    result.upgrades[bounded(line.substr(5, name_end - 5), 255)] =
        bounded(line.substr(version_open + 1, version_end - version_open - 1), 255);
  }
  result.succeeded = true;
  return result;
}

std::string iso_timestamp(const char* path) {
  struct stat status{};
  if (stat(path, &status) != 0) return {};
  std::tm value{};
  if (!gmtime_r(&status.st_mtime, &value)) return {};
  std::array<char, 32> result{};
  return std::strftime(result.data(), result.size(), "%Y-%m-%dT%H:%M:%SZ", &value) ? result.data() : "";
}

std::string snapshot_id() {
  std::array<unsigned char, 16> bytes{};
  if (RAND_bytes(bytes.data(), bytes.size()) != 1) return {};
  bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
  bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);
  std::ostringstream value;
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    if (index == 4 || index == 6 || index == 8 || index == 10) value << '-';
    value << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(bytes[index]);
  }
  return value.str();
}
}  // namespace

namespace ipms::agent::linux {

std::string collect_linux_inventory_json() {
  const auto release = os_release();
  const auto hostname = hostname_value();
  utsname system{};
  uname(&system);
  const auto manufacturer = bounded(read_text("/sys/class/dmi/id/sys_vendor", 1'024), 255);
  const auto model = bounded(read_text("/sys/class/dmi/id/product_name", 1'024), 255);
  std::ostringstream json;
  json << "{\"schema_version\":\"1\",\"pack\":\"linux-core\",\"agent_gateway_port\":9419,"
       << "\"hostname\":\"" << json_escape(hostname) << "\",\"fqdn\":\""
       << json_escape(fqdn_value(hostname)) << "\",\"distribution\":\""
       << json_escape(release.contains("NAME") ? release.at("NAME") : "Linux")
       << "\",\"distribution_version\":\""
       << json_escape(release.contains("VERSION_ID") ? release.at("VERSION_ID") : "")
       << "\",\"kernel_version\":\"" << json_escape(system.release)
       << "\",\"architecture\":\"" << json_escape(system.machine)
       << "\",\"manufacturer\":\"" << json_escape(manufacturer)
       << "\",\"model\":\"" << json_escape(model)
       << "\",\"serial_number\":\""
       << json_escape(bounded(read_text("/sys/class/dmi/id/product_serial", 1'024), 255))
       << "\",\"machine_type\":\"" << machine_type(manufacturer, model)
       << "\",\"logical_processors\":" << std::max(1U, std::thread::hardware_concurrency())
       << ",\"memory_total_bytes\":" << memory_total_bytes()
       << ",\"network_interfaces\":" << network_json()
       << ",\"fixed_volumes\":" << volumes_json() << "}";
  return json.str();
}

std::vector<std::string> collect_linux_software_inventory_pages() {
  const auto scan = apt_upgrades();
  std::ifstream input("/var/lib/dpkg/status");
  std::vector<std::string> package_items;
  std::map<std::string, std::string> fields;
  auto flush = [&]() {
    if (fields["Status"] != "install ok installed" || fields["Package"].empty()) {
      fields.clear();
      return;
    }
    const auto name = bounded(fields["Package"], 255);
    const auto architecture = bounded(fields["Architecture"], 64);
    const auto upgrade = scan.upgrades.find(name);
    const auto available = upgrade == scan.upgrades.end() ? "" : upgrade->second;
    auto source_id = "dpkg:" + name + ':' + architecture;
    if (source_id.size() > 255) {
      std::hash<std::string> hasher;
      source_id = "dpkg-hash:" + std::to_string(hasher(source_id));
    }
    std::ostringstream item;
    item << "{\"source_id\":\"" << json_escape(source_id)
         << "\",\"name\":\"" << json_escape(name) << "\",\"installed_version\":\""
         << json_escape(bounded(fields["Version"], 255)) << "\",\"available_version\":\""
         << json_escape(available) << "\",\"publisher\":\"\",\"package_type\":\"deb\","
         << "\"update_state\":\""
         << (!scan.succeeded ? "unknown" : (available.empty() ? "current" : "update-available"))
         << "\",\"is_os_component\":true}";
    package_items.push_back(item.str());
    fields.clear();
  };
  for (std::string line; std::getline(input, line) && package_items.size() < k_max_packages;) {
    if (line.empty()) {
      flush();
      continue;
    }
    if (!line.empty() && std::isspace(static_cast<unsigned char>(line.front()))) continue;
    const auto separator = line.find(':');
    if (separator != std::string::npos) fields[line.substr(0, separator)] = trim(line.substr(separator + 1));
  }
  if (!fields.empty() && package_items.size() < k_max_packages) flush();
  std::vector<std::vector<std::string>> pages(1);
  std::size_t page_bytes = 0;
  for (const auto& item : package_items) {
    if (!pages.back().empty() &&
        (pages.back().size() >= k_max_page_items || page_bytes + item.size() > k_max_page_item_bytes)) {
      if (pages.size() >= 64) break;
      pages.emplace_back();
      page_bytes = 0;
    }
    pages.back().push_back(item);
    page_bytes += item.size() + 1;
  }
  const auto id = snapshot_id();
  if (id.empty()) return {};
  const auto scan_time = iso_timestamp("/var/lib/apt/lists");
  const auto install_time = iso_timestamp("/var/log/dpkg.log");
  std::vector<std::string> result;
  for (std::size_t page_index = 0; page_index < pages.size(); ++page_index) {
    std::ostringstream json;
    json << "{\"schema_version\":\"1\",\"platform\":\"linux\",\"snapshot_id\":\""
         << id << "\",\"page_index\":" << page_index << ",\"page_count\":" << pages.size()
         << ",\"reboot_required\":" << (access("/var/run/reboot-required", F_OK) == 0 ? "true" : "false")
         << ",\"update_scan_status\":\""
         << (!scan.succeeded ? "unavailable" : (scan.upgrades.empty() ? "current" : "updates-available"))
         << "\",\"last_update_scan_at\":" << (scan_time.empty() ? "null" : "\"" + scan_time + "\"")
         << ",\"last_update_install_at\":" << (install_time.empty() ? "null" : "\"" + install_time + "\"")
         << ",\"packages\":[";
    for (std::size_t item_index = 0; item_index < pages[page_index].size(); ++item_index) {
      if (item_index) json << ',';
      json << pages[page_index][item_index];
    }
    json << "]}";
    result.push_back(json.str());
  }
  return result;
}

}  // namespace ipms::agent::linux
