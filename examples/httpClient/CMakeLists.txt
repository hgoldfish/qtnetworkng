cmake_minimum_required(VERSION 2.8.8 FATAL_ERROR)

project(httpClient)

find_package(Qt5Core REQUIRED)

add_subdirectory(../../ qtnetworkng)
add_executable(http_get main.cpp)

target_link_libraries(http_get PRIVATE qtnetworkng)
