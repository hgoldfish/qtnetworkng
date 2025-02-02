cmake_minimum_required(VERSION 2.8.8 FATAL_ERROR)

project(qtng_tests LANGUAGES CXX)

if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
else()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -z noexecstack")
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. qtnetworkng)

find_package(Qt5Core REQUIRED)
find_package(Qt5Test REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

enable_testing()

add_executable(test_threadqueue test_threadqueue.cpp)
target_link_libraries(test_threadqueue PRIVATE Qt5::Test Qt5::Core qtnetworkng)
add_test(qtng_tests test_threadqueue)

add_executable(test_kcp test_kcp.cpp)
target_link_libraries(test_kcp PRIVATE Qt5::Core qtnetworkng)

add_executable(test_kcpserver test_kcpserver.cpp)
target_link_libraries(test_kcpserver PRIVATE Qt5::Core qtnetworkng)

add_executable(test_websocket test_websocket.cpp)
target_link_libraries(test_websocket PRIVATE Qt5::Core qtnetworkng)

add_executable(test_websocket_server test_websocket_server.cpp)
target_link_libraries(test_websocket_server PRIVATE Qt5::Core qtnetworkng)

add_executable(test_lmdb test_lmdb.cpp)
target_link_libraries(test_lmdb PRIVATE Qt5::Core Qt5::Test qtnetworkng)
add_test(qtng_tests test_lmdb)
