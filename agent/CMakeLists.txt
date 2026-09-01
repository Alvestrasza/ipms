cmake_minimum_required(VERSION 3.24)

project(ipms_agent VERSION 0.1.19 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ipms_agent_core STATIC src/configuration.cpp src/gateway_contract.cpp src/management_pack.cpp)
target_include_directories(ipms_agent_core PUBLIC include)
target_compile_features(ipms_agent_core PUBLIC cxx_std_20)

add_executable(ipms-agent src/main.cpp)
target_link_libraries(ipms-agent PRIVATE ipms_agent_core)

if(WIN32)
  target_sources(ipms-agent PRIVATE src/windows/windows_core_pack.cpp src/windows/windows_service.cpp src/windows/windows_transport.cpp)
  target_link_libraries(ipms-agent PRIVATE advapi32 bcrypt crypt32 ncrypt ole32 oleaut32 winhttp)
  target_compile_definitions(ipms-agent PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
  add_executable(ipms-agent-config WIN32
    src/windows/configuration_app.cpp
    src/windows/resources/ipms-agent-config.rc
  )
  target_link_libraries(ipms-agent-config PRIVATE ipms_agent_core advapi32 user32)
  target_compile_definitions(ipms-agent-config PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
else()
  target_sources(ipms-agent PRIVATE src/linux/linux_service.cpp)
endif()

include(CTest)
if(BUILD_TESTING)
  add_executable(ipms-agent-pack-tests tests/management_pack_tests.cpp)
  target_link_libraries(ipms-agent-pack-tests PRIVATE ipms_agent_core)
  add_test(NAME management-pack-contract COMMAND ipms-agent-pack-tests)
endif()
