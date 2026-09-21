// File Name: windows_hgs_management.hpp
// Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Protected HGS state and isolated, release-bound Windows provider.
#pragma once
#include "ipms/agent/hgs_management.hpp"
#include <memory>
namespace ipms::agent::windows {
std::optional<hgs::journal> load_hgs_journal();
std::optional<hgs::journal> load_hgs_receipt(const hgs::job& assignment);
void save_hgs_journal(const hgs::journal& record);
std::optional<hgs::journal> load_hgs_fence();
void release_hgs_fence(const hgs::json::object& release);
void* acquire_hgs_lock();
std::unique_ptr<hgs::provider> make_hgs_provider(const std::function<bool()>& cancelled);
}  // namespace ipms::agent::windows
