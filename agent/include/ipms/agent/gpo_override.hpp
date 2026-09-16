// File Name: gpo_override.hpp
// Version: v0.1.0 | Created: 2026-09-16 | Last Modified: 2026-09-16
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Compiled-source-bound sparse GPO override validation and payload rendering.
#pragma once
#include "ipms/agent/gpo_management.hpp"

namespace ipms::agent::gpo {
bool override_job(const job& assignment);
std::string override_digest(const job& assignment);
void validate_override_job(const job& assignment);
// Every returned path is from the compiled original component, never the request.
std::map<std::string,std::string> render_override_files(const job& assignment);
}
