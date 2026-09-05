cmake_minimum_required(VERSION 3.24)

project(ipms_agent VERSION 0.2.26 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  # Socket, callback and credential lifetimes rely on C++ stack unwinding.
  # Keep it explicit even if an external build environment clears CXXFLAGS.
  add_compile_options(/EHsc)
endif()

add_library(ipms_agent_core STATIC src/configuration.cpp src/gateway_contract.cpp src/management_pack.cpp)
target_include_directories(ipms_agent_core PUBLIC include)
target_compile_features(ipms_agent_core PUBLIC cxx_std_20)

if(MSVC)
  target_compile_options(ipms_agent_core PRIVATE /W4 /permissive-)
endif()

add_executable(ipms-agent src/main.cpp)
target_link_libraries(ipms-agent PRIVATE ipms_agent_core)

if(WIN32)
  target_sources(ipms-agent PRIVATE src/windows/hyperv_pack.cpp src/windows/updater.cpp src/windows/windows_core_pack.cpp src/windows/windows_service.cpp src/windows/windows_software_pack.cpp src/windows/windows_telemetry.cpp src/windows/windows_transport.cpp src/windows/windows_native_console.cpp)
  target_link_libraries(ipms-agent PRIVATE advapi32 bcrypt crypt32 iphlpapi ncrypt ole32 oleaut32 shell32 wbemuuid windowscodecs winhttp ws2_32)
  target_compile_definitions(ipms-agent PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
  target_compile_options(ipms-agent PRIVATE /W4 /permissive-)
  add_executable(ipms-agent-config WIN32
    src/windows/configuration_app.cpp
    src/windows/resources/ipms-agent-config.rc
  )
  target_link_libraries(ipms-agent-config PRIVATE ipms_agent_core advapi32 user32)
  target_compile_definitions(ipms-agent-config PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
  target_compile_options(ipms-agent-config PRIVATE /W4 /permissive-)
  set_target_properties(ipms-agent-config PROPERTIES LINK_FLAGS "/MANIFEST:NO")
  add_executable(ipms-agent-updater src/windows/updater.cpp src/windows/updater_main.cpp)
  target_include_directories(ipms-agent-updater PRIVATE include)
  target_link_libraries(ipms-agent-updater PRIVATE advapi32 bcrypt shell32)
  target_compile_definitions(ipms-agent-updater PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
  target_compile_options(ipms-agent-updater PRIVATE /W4 /permissive-)
else()
  find_package(CURL REQUIRED)
  find_package(OpenSSL REQUIRED)
  target_sources(ipms-agent PRIVATE
    src/linux/linux_inventory.cpp
    src/linux/linux_service.cpp
    src/linux/linux_transport.cpp
  )
  target_link_libraries(ipms-agent PRIVATE CURL::libcurl OpenSSL::Crypto OpenSSL::SSL)
  target_compile_options(ipms-agent PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

include(CTest)
if(BUILD_TESTING)
  add_executable(ipms-agent-pack-tests tests/management_pack_tests.cpp)
  target_link_libraries(ipms-agent-pack-tests PRIVATE ipms_agent_core)
  if(MSVC)
    target_compile_options(ipms-agent-pack-tests PRIVATE /W4 /permissive-)
  endif()
  add_test(NAME management-pack-contract COMMAND ipms-agent-pack-tests)
  add_executable(ipms-agent-console-input-tests tests/console_input_tests.cpp)
  target_link_libraries(ipms-agent-console-input-tests PRIVATE ipms_agent_core)
  if(MSVC)
    target_compile_options(ipms-agent-console-input-tests PRIVATE /W4 /permissive-)
  endif()
  add_test(NAME console-input-isolation COMMAND ipms-agent-console-input-tests)
  add_executable(ipms-agent-worker-isolation-tests tests/worker_isolation_tests.cpp)
  target_link_libraries(ipms-agent-worker-isolation-tests PRIVATE ipms_agent_core)
  if(MSVC)
    target_compile_options(ipms-agent-worker-isolation-tests PRIVATE /W4 /permissive-)
  endif()
  add_test(NAME service-worker-isolation COMMAND ipms-agent-worker-isolation-tests)
  add_executable(ipms-agent-native-console-tests tests/native_console_guard_tests.cpp)
  target_link_libraries(ipms-agent-native-console-tests PRIVATE ipms_agent_core)
  if(MSVC)
    target_compile_options(ipms-agent-native-console-tests PRIVATE /W4 /permissive-)
  endif()
  add_test(NAME native-console-guards COMMAND ipms-agent-native-console-tests)
  if(WIN32)
    add_test(NAME embedded-updater-rejects-incomplete-command COMMAND ipms-agent --apply-lifecycle-update)
    set_tests_properties(embedded-updater-rejects-incomplete-command PROPERTIES WILL_FAIL TRUE)
    add_test(NAME standalone-updater-rejects-incomplete-command COMMAND ipms-agent-updater)
    set_tests_properties(standalone-updater-rejects-incomplete-command PROPERTIES WILL_FAIL TRUE)
  endif()
endif()
