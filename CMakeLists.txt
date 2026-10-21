cmake_minimum_required(VERSION 3.25)
project(warden_core VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WARDEN_BUILD_TESTS "Build warden-core tests" ${PROJECT_IS_TOP_LEVEL})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Warnings)
include(Dependencies)

add_library(warden_core STATIC src/version.cpp)
add_library(warden::core ALIAS warden_core)
target_include_directories(warden_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(warden_core PUBLIC cxx_std_17)
target_compile_definitions(warden_core PRIVATE WARDEN_CORE_VERSION="${PROJECT_VERSION}")
target_link_libraries(warden_core PRIVATE warden_warnings)

if(WARDEN_BUILD_TESTS)
    enable_testing()
    include(GoogleTest)
    file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*_test.cpp")
    # alloc_test.cpp is its own executable with a custom main (added by a later task).
    list(FILTER TEST_SOURCES EXCLUDE REGEX "alloc_test\\.cpp$")
    add_executable(warden_tests ${TEST_SOURCES})
    target_link_libraries(warden_tests PRIVATE warden::core warden_warnings GTest::gtest_main)
    gtest_discover_tests(warden_tests)
endif()
