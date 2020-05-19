cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(kcptun)

find_package(Qt5Core REQUIRED)
add_subdirectory(../../ qtnetworkng)

# Fix Qt-static cmake BUG
# https://bugreports.qt.io/browse/QTBUG-38913
if(EXISTS ${_qt5Core_install_prefix}/lib/libQt5Core.a AND NOT EXISTS ${_qt5Core_install_prefix}/bin/Qt5Core.dll)
    message("Static Qt is detected.")
    link_directories(${_qt5Core_install_prefix}/lib/)
endif()


add_executable(kcptun-server server.cpp)
target_link_libraries(kcptun-server PRIVATE qtnetworkng)

add_executable(kcptun-client client.cpp)
target_link_libraries(kcptun-client PRIVATE qtnetworkng)
