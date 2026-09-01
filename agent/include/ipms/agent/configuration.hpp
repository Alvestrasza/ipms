#pragma once

#include <cstdint>
#include <string>

namespace ipms::agent {

enum class TrustMode {
  ipms_managed,
  external_issuing_ca,
  external_certificates,
};

struct AgentConfiguration {
  std::wstring gateway_hostname;
  std::uint16_t gateway_port{9419};
  TrustMode trust_mode{TrustMode::ipms_managed};
};

bool is_valid_agent_configuration(const AgentConfiguration& configuration);
std::wstring trust_mode_name(TrustMode mode);
TrustMode parse_trust_mode(const std::wstring& value);

}  // namespace ipms::agent
