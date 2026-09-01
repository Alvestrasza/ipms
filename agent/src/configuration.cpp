#include "ipms/agent/configuration.hpp"

#include <algorithm>
#include <cwctype>

namespace ipms::agent {

bool is_valid_agent_configuration(const AgentConfiguration& configuration) {
  return configuration.gateway_port != 0 &&
         std::any_of(configuration.gateway_hostname.begin(), configuration.gateway_hostname.end(),
                     [](wchar_t character) { return !std::iswspace(character); });
}

std::wstring trust_mode_name(TrustMode mode) {
  switch (mode) {
    case TrustMode::ipms_managed: return L"ipms_managed";
    case TrustMode::external_issuing_ca: return L"external_issuing_ca";
    case TrustMode::external_certificates: return L"external_certificates";
  }
  return L"ipms_managed";
}

TrustMode parse_trust_mode(const std::wstring& value) {
  if (value == L"external_issuing_ca") return TrustMode::external_issuing_ca;
  if (value == L"external_certificates") return TrustMode::external_certificates;
  return TrustMode::ipms_managed;
}

}  // namespace ipms::agent
