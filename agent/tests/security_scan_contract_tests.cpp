// File Name: security_scan_contract_tests.cpp
// Version: v0.1.0
// Created: 2026-09-14
// Last Modified: 2026-09-14
// Author: Alice Endelgard
// Organization: Alvestrasza Corporation
// Description: Baseline scan identity, exact result-set and evidence boundary tests.
#include "ipms/agent/security_baseline.hpp"

#include <iostream>
#include <stdexcept>

namespace security = ipms::agent::security;
namespace json = ipms::agent::management_json;
namespace {
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
template <typename F> void rejects(F operation) {
  bool rejected = false;
  try { operation(); } catch (...) { rejected = true; }
  require(rejected, "Invalid scan contract accepted");
}
constexpr security::control_descriptor controls[]{
    {"setting-a", security::probe_kind::registry_value, "machine", "SOFTWARE\\Policies\\Example", "Setting", "dword"},
    {"setting-b", security::probe_kind::unsupported, "user", "", "", ""}};
constexpr security::baseline_descriptor baseline{"example", "server",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "26100", controls};
security::scan_job job() {
  return {"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
      "example", "server", std::string(baseline.manifest_sha256), 2, "2099-01-01T12:00:00Z"};
}
json::object system() { return {{"os_build", "26100"}, {"product_type", 3},
    {"operating_system", "Windows Server 2025 Datacenter"}, {"join_state", "domain"}}; }
std::vector<json::object> pages() { return security::make_pages(job(), baseline, system(),
    {security::observation("setting-a", "ok", 1), security::observation("setting-b", "unsupported")}); }
}
int main() {
  try {
    require(security::valid_descriptor(baseline), "Valid compiled descriptor rejected");
    require(security::parse_job(security::job_document(job())) == job(), "Job binding changed");
    auto document = security::job_document(job()); document["command"] = "forbidden";
    rejects([&] { security::parse_job(document); });
    document = security::job_document(job()); document["total_controls"] = 0;
    rejects([&] { security::parse_job(document); });
    document["total_controls"] = 2049; rejects([&] { security::parse_job(document); });
    document = security::job_document(job()); document["attempt_id"] = "invalid";
    rejects([&] { security::parse_job(document); });
    document = security::job_document(job()); document["profile"] = "domain-admin";
    rejects([&] { security::parse_job(document); });
    document = security::job_document(job()); document["expires_at"] = "2099-02-30T12:00:00Z";
    rejects([&] { security::parse_job(document); });
    auto valid = pages(); security::validate_pages(job(), baseline, valid);
    auto invalid = valid; invalid[0]["attempt_id"] = "33333333-3333-4333-8333-333333333333";
    rejects([&] { security::validate_pages(job(), baseline, invalid); });
    invalid = valid; invalid[0].at("controls").as<json::array>().pop_back();
    rejects([&] { security::validate_pages(job(), baseline, invalid); });
    invalid = valid; invalid[0].at("controls").as<json::array>()[1] = security::observation("setting-a", "unsupported");
    rejects([&] { security::validate_pages(job(), baseline, invalid); });
    invalid = valid; invalid[0]["page_index"] = 1;
    rejects([&] { security::validate_pages(job(), baseline, invalid); });
    invalid = valid; invalid[0].at("system").as<json::object>()["product_type"] = 2;
    rejects([&] { security::validate_pages(job(), baseline, invalid); });
    rejects([&] { security::observation("setting-a", "compliant", true); });
    rejects([&] { security::observation("setting-a", "missing", 0); });
    rejects([&] { security::observation("setting-a", "ok", std::string(1025, 'x')); });
    rejects([&] { security::observation("setting-a", "ok", json::array(33, "item")); });
    rejects([&] { security::observation("setting-a", "ok", true); });
    rejects([&] { security::observation("setting-a", "ok", -1); });
    rejects([&] { security::observation("setting-a", "ok", 4294967296LL); });
    require(security::observation("setting-a", "ok", 4294967295LL).at("value").as<std::int64_t>() == 4294967295LL,
            "Valid unsigned DWORD boundary rejected");
    require(security::observation("setting-a", "ok", json::array{}).at("value").as<json::array>().empty(),
            "Empty user-right assignment must remain a measured empty set");
    auto wrong = system(); wrong["os_build"] = "20348";
    require(!security::scope_matches(baseline, wrong), "Wrong operating-system build accepted");
    const auto* compiled = security::find_baseline("microsoft-windows-server-2025", "server");
    require(compiled && security::valid_descriptor(*compiled) && compiled->controls.size() >= 300,
            "Complete imported server profile unavailable");
    require(security::find_baseline("arbitrary", "server") == nullptr, "Arbitrary baseline accepted");
    std::cout << "PASS: strict job identity, bounded observations, exact pages, scope and compiled catalog.\n";
    return 0;
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
