cmake_minimum_required(VERSION 3.20)
project(vanta_pattern_scan_lab LANGUAGES CXX)

add_executable(pattern_scan_tests tests/pattern_scan_tests.cpp)
target_include_directories(pattern_scan_tests PRIVATE include)
target_compile_features(pattern_scan_tests PRIVATE cxx_std_17)

enable_testing()
add_test(NAME pattern_scan_tests COMMAND pattern_scan_tests)