cmake_minimum_required(VERSION 3.25)
project(guardian_core VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GUARDIAN_BUILD_TESTS "Build guardian-core tests" ${PROJECT_IS_TOP_LEVEL})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Warnings)
include(Dependencies)

add_library(guardian_core STATIC src/engine.cpp src/glob.cpp src/path.cpp src/policy_parser.cpp src/version.cpp)
add_library(guardian::core ALIAS guardian_core)
target_include_directories(guardian_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(guardian_core PUBLIC cxx_std_17)
target_compile_definitions(guardian_core PRIVATE GUARDIAN_CORE_VERSION="${PROJECT_VERSION}")
target_link_libraries(guardian_core PRIVATE guardian_warnings nlohmann_json::nlohmann_json)

if(GUARDIAN_BUILD_TESTS)
    enable_testing()
    include(GoogleTest)
    file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*_test.cpp")
    # alloc_test.cpp is its own executable with a custom main and no GoogleTest.
    list(FILTER TEST_SOURCES EXCLUDE REGEX "alloc_test\\.cpp$")
    add_executable(guardian_tests ${TEST_SOURCES})
    target_link_libraries(guardian_tests PRIVATE guardian::core guardian_warnings GTest::gtest_main)
    gtest_discover_tests(guardian_tests PROPERTIES TIMEOUT 10)
    add_executable(guardian_alloc_tests tests/alloc_test.cpp)
    target_link_libraries(guardian_alloc_tests PRIVATE guardian::core guardian_warnings)
    add_test(NAME guardian_alloc_tests COMMAND guardian_alloc_tests)
endif()
