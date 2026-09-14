// File Name: windows_gpo_management.hpp
// Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Purpose-bound local approval, storage and isolated GPMC worker.
#pragma once
#include "ipms/agent/gpo_management.hpp"
#include <filesystem>

namespace ipms::agent::windows {
std::filesystem::path gpo_storage_directory();
std::optional<gpo::journal> load_gpo_journal();
void save_gpo_journal(const gpo::journal& record);
bool has_gpo_local_approval(const gpo::job& job, std::string_view device_uri);
void consume_gpo_local_approval(const gpo::job& job, std::string_view device_uri);
void save_gpo_artifact(const gpo::job& job, std::string_view bytes);
std::filesystem::path expand_gpo_artifact(const gpo::job& job);
bool gpo_enrollment_matches(std::string_view device_uri);
// Caller closes the returned native handle. Sharing is disabled across processes.
void* acquire_gpo_cycle_lock();
int approve_gpo_pilot(const std::filesystem::path& document);
gpo::json::object probe_gpo_executor(const std::function<bool()>& cancelled = {});
gpo::json::object invoke_gpo_pilot_worker(const std::function<bool()>& cancelled = {});
int run_gpo_worker();

// Storage primitives are public only to allow real filesystem boundary tests in
// a disposable directory. Production callers always use gpo_storage_directory.
std::string read_protected_gpo_file(const std::filesystem::path& path, std::size_t limit);
void write_protected_gpo_file(const std::filesystem::path& path, std::string_view bytes, bool replace);
void ensure_gpo_directory(const std::filesystem::path& directory);
void verify_gpo_storage_parent(const std::filesystem::path& directory);
}  // namespace ipms::agent::windows
