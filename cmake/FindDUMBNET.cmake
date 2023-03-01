# - Try to find libdumbnet include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(DUMBNET)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  DUMPNET_ROOT_DIR            Set this variable to the root installation of
#                              libpcap if the module has problems finding the
#                              proper installation path.
#
# Variables defined by this module:
#
#  DUMBNET_INCLUDE_DIR         The libdumbnet include directories
#  DUMBNET_LIBRARY             The libdumbnet library
#  DUMBNET_FOUND               System has libdumbnet, include and library dirs found
#  HAVE_LIBDUMBNET             True if found dumbnet

find_path(DUMPNET_ROOT_DIR
    NAMES include/dumbnet.h Include/dumbnet.h
)

find_path(DUMBNET_INCLUDE_DIR
    NAMES dumbnet.h
    HINTS ${DUMPNET_ROOT_DIR}/include
)

if ( MSVC AND COMPILER_ARCHITECTURE STREQUAL "x86_64" )
    set(_dumbnet_lib_hint_path ${DUMPNET_ROOT_DIR}/lib/x64)
else()
    set(_dumbnet_lib_hint_path ${DUMPNET_ROOT_DIR}/lib)
endif()

find_library(DUMBNET_LIBRARY
    NAMES dumbnet
    HINTS ${_dumbnet_lib_hint_path}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DUMBNET DEFAULT_MSG
    DUMBNET_LIBRARY
    DUMBNET_INCLUDE_DIR
)

mark_as_advanced(
    DUMPNET_ROOT_DIR
    DUMBNET_INCLUDE_DIR
    DUMBNET_LIBRARY
)

set(HAVE_LIBDUMBNET True)

message(STATUS "DUMBNET_INCLUDE_DIR ${DUMBNET_INCLUDE_DIR}")
message(STATUS "DUMBNET_LIBRARY ${DUMBNET_LIBRARY}")

add_library(dumbnet SHARED IMPORTED)
set_property(TARGET dumbnet PROPERTY
             IMPORTED_LOCATION "${DUMBNET_LIBRARY}")
target_include_directories(pcap INTERFACE ${DUMBNET_INCLUDE_DIR})
