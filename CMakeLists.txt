cmake_minimum_required(VERSION 3.14)

project(usipp LANGUAGES C CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set (CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(PCAP REQUIRED)
find_package(DUMBNET REQUIRED)


# Checks for header files.
include(CheckIncludeFiles)
foreach (header stdbool.h stdint.h stdlib.h strings.h string.h sys/ioctl.h sys/stat.h
    sys/types.h unistd.h netdb.h netinet/in.h inttypes.h memory.h)
  string(TOUPPER HAVE_${header} var)
  string(REGEX REPLACE "\\.|/" "_" var ${var})
  check_include_files(${header} ${var})
  message(STATUS "${var}")
endforeach ()
check_include_files(stdio.h STDC_HEADERS)

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES )
check_function_exists(gethostbyaddr HAVE_GETHOSTBYADDR)
check_function_exists(gethostbyname HAVE_GETHOSTBYNAME)
check_function_exists(gethostname HAVE_GETHOSTNAME)
check_function_exists(inet_ntoa HAVE_INET_NTOA)
check_function_exists(memset HAVE_MEMSET)
check_function_exists(select HAVE_SELECT)
check_function_exists(socket HAVE_SOCKET)
check_function_exists(strerror HAVE_STRERROR)


if (${HAVE_SOCKET})
    set(HAVE_LIBSOCKET True)
endif()

configure_file(config.h.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

file(GLOB_RECURSE files_cpp src/*.cc)
file(GLOB_RECURSE files_h usi++/*.h)

add_library(
  ${PROJECT_NAME} STATIC
  ${files_cpp} ${files_h})


target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC pcap dumbnet)

add_subdirectory(samples)
