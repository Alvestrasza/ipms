// File Name: windows_gpo_management.hpp
// Version: v0.2.0 | Created: 2026-09-14 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Separate local and portal approval receipts, protected storage and isolated GPMC worker.
#pragma once
#include "ipms/agent/gpo_management.hpp"
#include "ipms/agent/gpo_managed.hpp"
#include "ipms/agent/gpo_reconciliation.hpp"
#include <memory>
#include <filesystem>

namespace ipms::agent::windows {
std::filesystem::path gpo_storage_directory();
std::optional<gpo::journal> load_gpo_journal();
void save_gpo_journal(const gpo::journal& record);
bool has_gpo_local_approval(const gpo::job& job, std::string_view device_uri);
void consume_gpo_local_approval(const gpo::job& job, std::string_view device_uri);
void save_gpo_portal_approval(const gpo::journal& record);
bool has_gpo_portal_approval(const gpo::journal& record);
void consume_gpo_portal_approval(const gpo::journal& record);
void save_gpo_artifact(const gpo::job& job, std::string_view bytes);
std::filesystem::path expand_gpo_artifact(const gpo::job& job);
bool gpo_enrollment_matches(std::string_view device_uri);
// Caller closes the returned native handle. Sharing is disabled across processes.
void* acquire_gpo_cycle_lock();
void* acquire_gpo_worker_lock();
std::string gpo_journal_sha256(const gpo::journal& record);
void save_gpo_reconciliation_request(const gpo::journal& record, const gpo::json::object& challenge);
gpo::json::object load_gpo_reconciliation_request(const gpo::journal& record);
void save_gpo_reconciliation_pending(const gpo::journal& record, const gpo::json::object& sidecar);
gpo::json::object load_gpo_reconciliation_pending(const gpo::journal& record, std::string_view id);
void save_gpo_reconciliation_release(const gpo::journal& record, const gpo::json::object& sidecar);
bool has_gpo_reconciliation_release(const gpo::journal& record);
bool gpo_worker_quiescent();
gpo::json::object invoke_gpo_reconciliation_worker(const std::function<bool()>& cancelled = {});
gpo::json::object observe_gpo_reconciliation(const gpo::journal& record, const gpo::json::object& executor);
int approve_gpo_pilot(const std::filesystem::path& document);
gpo::json::object probe_gpo_executor(const std::function<bool()>& cancelled = {});
gpo::json::object invoke_gpo_pilot_worker(const std::function<bool()>& cancelled = {});
int run_gpo_worker();
std::unique_ptr<gpo::managed_provider> make_managed_gpo_provider(const gpo::job& job, const gpo::json::object& executor_identity);
gpo::json::object invoke_gpo_inspection_worker(const std::function<bool()>& cancelled = {});

// Storage primitives are public only to allow real filesystem boundary tests in
// a disposable directory. Production callers always use gpo_storage_directory.
std::string read_protected_gpo_file(const std::filesystem::path& path, std::size_t limit);
void write_protected_gpo_file(const std::filesystem::path& path, std::string_view bytes, bool replace);
void consume_protected_gpo_file(const std::filesystem::path& path, const std::filesystem::path& consumed,
    std::string_view expected_bytes);
void ensure_gpo_directory(const std::filesystem::path& directory);
void verify_gpo_storage_parent(const std::filesystem::path& directory);
}  // namespace ipms::agent::windows
