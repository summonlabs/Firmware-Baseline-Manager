cmake_minimum_required(VERSION 3.25)

project(FirmwareBaselineManager
        VERSION 1.0.0
        DESCRIPTION "DCCP facility-level firmware baseline policy and conformance authority"
        HOMEPAGE_URL "https://github.com/summonlabs/Firmware-Baseline-Manager"
        LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(FBM_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(FBM_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer where supported" OFF)
option(FBM_BUILD_BENCHMARKS "Build the Firmware Baseline Manager benchmarks" OFF)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Strict first-party warnings
# ---------------------------------------------------------------------------
function(fbm_strict_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor /Zc:throwingNew)
    if(FBM_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wold-style-cast -Wcast-qual -Wcast-align
      -Wnon-virtual-dtor -Woverloaded-virtual -Wdouble-promotion -Wformat=2
      -Wimplicit-fallthrough -Wunused -Wundef)
    if(FBM_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

# The MSVC AddressSanitizer runtime ships with the Visual Studio C++ workload but
# is not installed by every workload selection. It is probed at configure time so
# that a missing runtime is reported as a configuration problem with an actionable
# message, instead of a link error hundreds of build steps later.
if(FBM_ENABLE_SANITIZERS AND MSVC)
  include(CheckCXXSourceCompiles)
  set(CMAKE_REQUIRED_FLAGS "/fsanitize=address")
  set(CMAKE_REQUIRED_LINK_OPTIONS "/fsanitize=address")
  check_cxx_source_compiles("int main() { return 0; }" FBM_MSVC_ASAN_AVAILABLE)
  unset(CMAKE_REQUIRED_FLAGS)
  unset(CMAKE_REQUIRED_LINK_OPTIONS)
  if(NOT FBM_MSVC_ASAN_AVAILABLE)
    message(FATAL_ERROR
      "FBM_ENABLE_SANITIZERS=ON, but this MSVC toolchain cannot link an "
      "AddressSanitizer binary because the ASan runtime libraries are not "
      "installed. Install the \"C++ AddressSanitizer\" component for the "
      "Visual Studio C++ workload, or configure with FBM_ENABLE_SANITIZERS=OFF. "
      "This project never reports sanitizer results it did not observe.")
  endif()
endif()

function(fbm_sanitizers target)
  if(NOT FBM_ENABLE_SANITIZERS)
    return()
  endif()
  if(MSVC)
    # Debug information is required: without it the compiler emits C5072, which
    # the strict warning policy turns into an error, and an ASan report without
    # line information is far less useful.
    target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
    target_link_options(${target} PRIVATE /fsanitize=address /DEBUG)
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(FBM_PUBLIC_HEADERS
  include/summon/fbm/version.hpp
  include/summon/fbm/error.hpp
  include/summon/fbm/result.hpp
  include/summon/fbm/strong_types.hpp
  include/summon/fbm/identifier.hpp
  include/summon/fbm/timestamp.hpp
  include/summon/fbm/firmware_version.hpp
  include/summon/fbm/crypto.hpp
  include/summon/fbm/json.hpp
  include/summon/fbm/compatibility.hpp
  include/summon/fbm/baseline.hpp
  include/summon/fbm/observation.hpp
  include/summon/fbm/exception.hpp
  include/summon/fbm/cohort.hpp
  include/summon/fbm/conformance.hpp
  include/summon/fbm/authority.hpp
  include/summon/fbm/policy_document.hpp
  include/summon/fbm/snapshot.hpp
  include/summon/fbm/store.hpp
  include/summon/fbm/engine.hpp
  include/summon/fbm/manager.hpp
  include/summon/fbm/platform.hpp
  include/summon/fbm/text_format.hpp
  include/summon/fbm/cli.hpp
)

set(FBM_SOURCES
  src/version.cpp
  src/error.cpp
  src/timestamp.cpp
  src/firmware_version.cpp
  src/crypto.cpp
  src/json.cpp
  src/identifier.cpp
  src/compatibility.cpp
  src/baseline.cpp
  src/observation.cpp
  src/exception.cpp
  src/cohort.cpp
  src/conformance.cpp
  src/authority.cpp
  src/policy_document.cpp
  src/snapshot.cpp
  src/store.cpp
  src/platform.cpp
  src/engine.cpp
  src/manager.cpp
  src/text_format.cpp
  src/cli.cpp
)

add_library(fbm STATIC ${FBM_SOURCES} ${FBM_PUBLIC_HEADERS})
add_library(Summon::FirmwareBaselineManager ALIAS fbm)

set_target_properties(fbm PROPERTIES
  EXPORT_NAME FirmwareBaselineManager
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON)

target_include_directories(fbm
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_compile_definitions(fbm
  PUBLIC FBM_VERSION_STRING="${PROJECT_VERSION}"
  PRIVATE FBM_BUILDING_LIBRARY=1)

if(MSVC)
  # Applied to every target in this project so that a single translation unit
  # cannot silently be exempt from the same warning policy as the rest.
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

fbm_strict_warnings(fbm)
fbm_sanitizers(fbm)

# ---------------------------------------------------------------------------
# Command-line tool
# ---------------------------------------------------------------------------
add_executable(fbm_cli apps/fbm_main.cpp)
set_target_properties(fbm_cli PROPERTIES OUTPUT_NAME fbm EXPORT_NAME FirmwareBaselineManagerCli)
target_link_libraries(fbm_cli PRIVATE fbm)
fbm_strict_warnings(fbm_cli)
fbm_sanitizers(fbm_cli)

# ---------------------------------------------------------------------------
# Test harness executables (built only for the in-tree test suite)
# ---------------------------------------------------------------------------
if(BUILD_TESTING)
  add_executable(fbm_proc_tool apps/fbm_proc_tool.cpp)
  target_link_libraries(fbm_proc_tool PRIVATE fbm)
  fbm_strict_warnings(fbm_proc_tool)
  fbm_sanitizers(fbm_proc_tool)

  add_executable(fbm_crash_tool apps/fbm_crash_tool.cpp)
  target_link_libraries(fbm_crash_tool PRIVATE fbm)
  fbm_strict_warnings(fbm_crash_tool)
  fbm_sanitizers(fbm_crash_tool)

  add_executable(fbm_tests
    tests/test_main.cpp
    tests/test_version_and_types.cpp
    tests/test_timestamp.cpp
    tests/test_firmware_version.cpp
    tests/test_crypto.cpp
    tests/test_json.cpp
    tests/test_compatibility.cpp
    tests/test_baseline.cpp
    tests/test_observation.cpp
    tests/test_exception.cpp
    tests/test_cohort.cpp
    tests/test_conformance.cpp
    tests/test_authority.cpp
    tests/test_policy_document.cpp
    tests/test_snapshot.cpp
    tests/test_store.cpp
    tests/test_recovery.cpp
    tests/test_lock_and_multiprocess.cpp
    tests/test_property.cpp
    tests/test_state_machine.cpp
    tests/test_adversarial.cpp
    tests/test_concurrency.cpp
    tests/test_manager.cpp
    tests/test_cli.cpp
    tests/test_installed_artifact.cpp)

  target_include_directories(fbm_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")
  target_link_libraries(fbm_tests PRIVATE fbm)
  # The harness paths are baked in as a configure-time directory with forward
  # slashes plus the bare executable name. A native Windows path would put
  # backslashes inside a C++ string literal, where they are read as escape
  # sequences, and no generator expression converts separators portably.
  file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}" FBM_TEST_BINARY_DIR)
  target_compile_definitions(fbm_tests PRIVATE
    FBM_PROC_TOOL_PATH="${FBM_TEST_BINARY_DIR}/$<TARGET_FILE_NAME:fbm_proc_tool>"
    FBM_CRASH_TOOL_PATH="${FBM_TEST_BINARY_DIR}/$<TARGET_FILE_NAME:fbm_crash_tool>"
    FBM_CLI_PATH="${FBM_TEST_BINARY_DIR}/$<TARGET_FILE_NAME:fbm_cli>")
  fbm_strict_warnings(fbm_tests)
  fbm_sanitizers(fbm_tests)

  add_test(NAME fbm.unit COMMAND fbm_tests)
  set_tests_properties(fbm.unit PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    ENVIRONMENT "FBM_TEST_SCRATCH=$<SHELL_PATH:${CMAKE_CURRENT_BINARY_DIR}/test-scratch>")

  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RunConsumerTest.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/RunConsumerTest.cmake"
    @ONLY)
  add_test(NAME fbm.packaging.consumer
    COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/RunConsumerTest.cmake")
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
if(FBM_BUILD_BENCHMARKS)
  add_executable(fbm_bench apps/fbm_bench.cpp)
  target_link_libraries(fbm_bench PRIVATE fbm)
  fbm_strict_warnings(fbm_bench)
  fbm_sanitizers(fbm_bench)
endif()

# ---------------------------------------------------------------------------
# Install / export / package
# ---------------------------------------------------------------------------
install(TARGETS fbm fbm_cli
  EXPORT FirmwareBaselineManagerTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(EXPORT FirmwareBaselineManagerTargets
  FILE FirmwareBaselineManagerTargets.cmake
  NAMESPACE Summon::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/FirmwareBaselineManager")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FirmwareBaselineManagerConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/FirmwareBaselineManagerConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/FirmwareBaselineManager")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/FirmwareBaselineManagerConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/FirmwareBaselineManagerConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/FirmwareBaselineManagerConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/FirmwareBaselineManager")

install(FILES README.md NOTICE LICENSE
  DESTINATION "${CMAKE_INSTALL_DATADIR}/FirmwareBaselineManager")
