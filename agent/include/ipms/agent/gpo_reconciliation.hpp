// File Name: gpo_reconciliation.hpp
// Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Read-only observations and exact immutable failure acceptance bindings.
#pragma once
#include "ipms/agent/gpo_managed.hpp"

namespace ipms::agent::gpo {
bool reconciliation_issue(std::string_view code);
json::object unavailable_observation(std::string_view guid, std::string_view issue, bool quiescent = false);
bool valid_reconciliation_observation(const json::value& value);
bool acceptable_reconciliation_observation(const journal& original, const json::object& observation);
json::object parse_reconciliation(const json::value& value, const journal& original,
    std::string_view journal_sha256, bool require_current = true);
json::object reconciliation_sidecar(const json::object& challenge, const json::object& observation);
bool valid_reconciliation_sidecar(const json::value& value, const journal& original,
    std::string_view journal_sha256, std::string_view mode);
json::object reconciliation_release(const json::object& released, const json::value& pending,
    const journal& original, std::string_view journal_sha256);
} // namespace ipms::agent::gpo
