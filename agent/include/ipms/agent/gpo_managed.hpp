// File Name: gpo_managed.hpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Snapshot-bound managed GPO operations and read-only inspection seam.
#pragma once
#include "ipms/agent/gpo_management.hpp"

namespace ipms::agent::gpo {
struct forest_domain {
  std::string dns_name;
  std::string guid;
  bool primary{};
  bool operator==(const forest_domain&) const = default;
};
void validate_forest_domains(const job& assignment, const std::vector<forest_domain>& domains);
std::optional<std::uint32_t> matching_gpo_link(std::string_view links, std::string_view policy_dn);
void verify_forest_link_census(const json::array& links, const std::map<std::string,std::uint32_t>& complete_locations);
bool managed_operation(std::string_view operation);
bool inspection(const job& assignment);
bool valid_snapshot(const json::value& state);
void validate_managed_job(const job& assignment);
bool valid_managed_result(const json::object& document);
void validate_managed_state(const job& assignment, const json::object& state);
json::object managed_evidence(const job& assignment, json::object state,
    std::string_view backup_id = {}, std::string_view backup_digest = {});

class managed_provider {
 public:
  virtual ~managed_provider() = default;
  virtual json::object inspect() = 0;
  virtual void prepare() = 0;
  virtual std::string create() = 0;
  virtual void initialize(std::string_view guid) = 0;
  virtual void adopt(std::string_view guid) = 0;
  virtual std::pair<std::string,std::string> backup(std::string_view guid) = 0;
  virtual void link(std::string_view guid) = 0;
  virtual void activate(std::string_view guid) = 0;
  virtual void deactivate(std::string_view guid) = 0;
};
json::object inspect_managed(journal& record, managed_provider& provider, const persist& save,
    const std::function<bool()>& authority);
json::object execute_managed(journal& record, managed_provider& provider, const persist& save,
    const std::function<bool()>& authority, const std::function<void()>& consume);
}  // namespace ipms::agent::gpo
