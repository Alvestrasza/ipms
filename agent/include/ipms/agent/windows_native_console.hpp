#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <cstdint>
#include <functional>
#include <string>

namespace ipms::agent::windows {

// An enrolled Gateway and a server-issued VM assignment are the only inputs.
// The local destination is compiled in; host credentials never enter the Agent.
void relay_native_hyperv_console(
    const std::wstring& gateway, std::uint16_t gateway_port,
    const std::string& session_id, const std::string& stream_generation,
    const std::string& vm_id, PCCERT_CONTEXT certificate,
    const std::function<bool()>& cancelled);

}  // namespace ipms::agent::windows
