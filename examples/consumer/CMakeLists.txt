cmake_minimum_required(VERSION 3.25)

# An independent out-of-tree consumer of the installed FirmwareBaselineManager
# package. It deliberately does not add_subdirectory the library and does not
# reference the source tree: it is built purely against the installed package
# found by find_package, which is what makes it a packaging proof rather than a
# second copy of the in-tree build.
project(FirmwareBaselineManagerConsumer LANGUAGES CXX)

find_package(FirmwareBaselineManager 1.0 CONFIG REQUIRED)

add_executable(fbm_consumer main.cpp)
target_compile_features(fbm_consumer PRIVATE cxx_std_20)
target_link_libraries(fbm_consumer PRIVATE Summon::FirmwareBaselineManager)

if(MSVC)
  target_compile_options(fbm_consumer PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
  target_compile_definitions(fbm_consumer PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(fbm_consumer PRIVATE -Wall -Wextra -Wpedantic)
endif()
