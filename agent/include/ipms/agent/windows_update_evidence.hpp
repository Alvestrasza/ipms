// File Name: windows_update_evidence.hpp
// Version: v0.1.0
// Created: 2026-09-13
// Last Modified: 2026-09-13
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Bounded positive installed-update evidence from the local WUA cache.
#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace ipms::agent::windows {

// The timeout may be lowered by local callers, never raised above 15 seconds.
// Uses a fixed child mode of the current executable; accepts no query or command.
std::string collect_windows_update_evidence_json(
    std::chrono::milliseconds timeout = std::chrono::seconds(15));

// Local fixed worker entry point. No network search, service registration,
// policy change, download, installation, or host restart is performed.
int run_windows_update_evidence_worker();

// Enforce the same bounded contract at the process boundary and in native tests.
// Invalid/partial input becomes unavailable; duplicates are normalized exactly.
std::string normalize_windows_update_evidence_json(std::string_view document);

}  // namespace ipms::agent::windows
