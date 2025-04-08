cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)
project(httpServer)

add_subdirectory(../../ qtnetworkng)

add_executable(httpd main.cpp)
target_link_libraries(httpd qtnetworkng)
