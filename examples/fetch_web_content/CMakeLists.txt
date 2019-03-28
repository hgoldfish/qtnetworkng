cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)
project(fetch_web_content)

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt5Widgets REQUIRED)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../ qtnetworkng)

add_executable(fetch_web_content main.cpp)
target_link_libraries(fetch_web_content Qt5::Widgets qtnetworkng)
