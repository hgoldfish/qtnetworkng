cmake_minimum_required(VERSION 2.8.8 FATAL_ERROR)

project(qtng_tests LANGUAGES CXX)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. qtnetworkng)

find_package(Qt5Core REQUIRED)
find_package(Qt5Test REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

enable_testing()

add_executable(test_threadqueue test_threadqueue.cpp)
target_link_libraries(test_threadqueue PRIVATE Qt5::Test Qt5::Core pthread qtnetworkng)
add_test(qtng_tests test_threadqueue)
