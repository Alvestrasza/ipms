#pragma once

#include "ipms/agent/hyperv_management_journal.hpp"
#include <filesystem>
#include <optional>

namespace ipms::agent::windows {

// Caller serializes access. The directory is a fixed child of the protected
// Agent data directory, never supplied by a Portal assignment.
std::optional<hyperv_management_journal::journal> load_management_journal(
    const std::filesystem::path& directory);
void save_management_journal(const std::filesystem::path& directory,
                             const hyperv_management_journal::journal& record);
// Only after an authenticated lookup proves cancellation before invocation.
void archive_prepared_management_journal(const std::filesystem::path& directory,
                                         const hyperv_management_journal::binding& identity);

}  // namespace ipms::agent::windows
