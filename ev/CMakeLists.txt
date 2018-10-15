cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(libev LANGUAGES C)

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckLibraryExists)

check_include_files(inttypeas.h HAVE_INTTYPES_H)
check_include_files(dlfcn.h HAVE_DLFCN_H)
check_include_files(memory.h HAVE_MEMORY_H)
check_include_files(poll.h HAVE_POLL_H)
check_include_files(port.h HAVE_PORT_H)
check_include_files(stdint.h HAVE_STDINT_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(strings.h HAVE_STRINGS_H)
check_include_files(string.h HAVE_STRING_H)
check_include_files(sys/epoll.h HAVE_SYS_EPOLL_H)
check_include_files(sys/eventfd.h HAVE_SYS_EVENTFD_H)
check_include_files(sys/event.h HAVE_SYS_EVENT_H)
#check_include_files(sys/inotify.h HAVE_SYS_INOTIFY_H)  # disabled for android.
check_include_files(sys/select.h HAVE_SYS_SELECT_H)
check_include_files(sys/signalfd.h HAVE_SYS_SIGNALFD_H)
check_include_files(sys/stat.h HAVE_SYS_STAT_H)
check_include_files(sys/types.h HAVE_SYS_TYPES_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files("assert.h;ctype.h;errno.h;float.h;limits.h;locale.h;math.h;setjmp.h;signal.h;stdarg.h;stddef.h;stdio.h;stdlib.h;string.h;time.h;" STDC_HEADERS)
check_include_files("winsock.h" HAVE_WINSOCK_H)

# check functions
check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)
check_function_exists(epoll_ctl HAVE_EPOLL_CTL)
check_function_exists(eventfd HAVE_EVENTFD)
check_function_exists(floor HAVE_FLOOR)
#check_function_exists(inotify_init HAVE_INOTIFY_INIT)   # disable for androd.
check_function_exists(kqueue HAVE_KQUEUE)
check_function_exists(nanosleep HAVE_NANOSLEEP)
check_function_exists(poll HAVE_POLL)
check_function_exists(port_create HAVE_PORT_CREATE)
check_function_exists(select HAVE_SELECT)
check_function_exists(signalfd HAVE_SIGNALFD)

# check system library
check_library_exists(rt pthread_create "" HAVE_LIBRT)

configure_file(config.h.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ev/)
# Ignore deprecation warnings and cast warnings
if(MSVC)
    add_definitions("/wd4244")
    add_definitions("/wd4996")
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set(OS_EXTRA_LINK ws2_32)
endif()

add_library(ev STATIC ev.c)
target_link_libraries(ev ${OS_EXTRA_LINK})

