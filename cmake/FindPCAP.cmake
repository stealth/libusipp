# - Try to find libpcap include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(PCAP)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  PCAP_ROOT_DIR               Set this variable to the root installation of
#                              libpcap if the module has problems finding the
#                              proper installation path.
#
# Variables defined by this module:
#
#  PCAP_FOUND                    System has libpcap, include and library dirs found
#  PCAP_INCLUDE_DIR              The libpcap include directories
#  PCAP_LIBRARY                  The libpcap library (possibly includes a thread
#                                library e.g. required by pf_ring's libpcap)
#  HAVE_PF_RING                  If a found version of libpcap supports PF_RING
#  HAVE_PCAP_DUMP_OPEN_APPEND    If a found version of libpcap supports DUMP_OPEN_APPEND
#  HAVE_PCAP_OPEN_LIVE           If a found version of libpcap supports OPEN_LIVE
#  HAVE_PCAP_INJECT              If a found version of libpcap supports INJECT
#  HAVE_RADIOTAP                 If a found version of libpcap supports RADIOTAP
#  HAVE_PCAP_SET_IMMEDIATE_MODE  If a found version of libpcap supports SET_IMMEDIATE_MODE


find_path(PCAP_ROOT_DIR
    NAMES include/pcap.h Include/pcap.h
)

find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
    HINTS ${PCAP_ROOT_DIR}/include
)

if ( MSVC AND COMPILER_ARCHITECTURE STREQUAL "x86_64" )
    set(_pcap_lib_hint_path ${PCAP_ROOT_DIR}/lib/x64)
else()
    set(_pcap_lib_hint_path ${PCAP_ROOT_DIR}/lib)
endif()

find_library(PCAP_LIBRARY
    NAMES pcap wpcap
    HINTS ${_pcap_lib_hint_path}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG
    PCAP_LIBRARY
    PCAP_INCLUDE_DIR
)

include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
check_c_source_compiles("int main() { return 0; }" PCAP_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)

# check if linking against libpcap also needs to link against a thread library
if (NOT PCAP_LINKS_SOLO)
    find_package(Threads)
    if (Threads_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
        check_c_source_compiles("int main() { return 0; }" PCAP_NEEDS_THREADS)
        set(CMAKE_REQUIRED_LIBRARIES)
    endif ()
    if (THREADS_FOUND AND PCAP_NEEDS_THREADS)
        set(_tmp ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
        list(REMOVE_DUPLICATES _tmp)
        set(PCAP_LIBRARY ${_tmp}
            CACHE STRING "Libraries needed to link against libpcap" FORCE)
    else ()
        message(FATAL_ERROR "Couldn't determine how to link against libpcap")
    endif ()
endif ()

string(FIND "${PCAP_LIBRARY}" "wpcap" _pcap_lib_is_wpcap)
if ( _pcap_lib_is_wpcap GREATER_EQUAL 0 )
    set(HAVE_WPCAP TRUE)
endif()

set(HAVE_LIBPCAP TRUE)

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
check_function_exists(pcap_get_pfring_id HAVE_PF_RING)
check_function_exists(pcap_dump_open_append HAVE_PCAP_DUMP_OPEN_APPEND)
check_function_exists(pcap_open_live HAVE_PCAP_OPEN_LIVE)
check_function_exists(pcap_inject HAVE_PCAP_INJECT)

include(CheckSymbolExists)
check_symbol_exists(DLT_IEEE802_11_RADIO ${PCAP_INCLUDE_DIR}/pcap/dlt.h HAVE_RADIOTAP)
check_symbol_exists(pcap_set_immediate_mode ${PCAP_INCLUDE_DIR}/pcap/pcap.h HAVE_PCAP_SET_IMMEDIATE_MODE)


set(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
    PCAP_ROOT_DIR
    PCAP_INCLUDE_DIR
    PCAP_LIBRARY
)

message(STATUS "PCAP_INCLUDE_DIR ${PCAP_INCLUDE_DIR}")
message(STATUS "PCAP_LIBRARY ${PCAP_LIBRARY}")

add_library(pcap SHARED IMPORTED)
set_property(TARGET pcap PROPERTY
             IMPORTED_LOCATION "${PCAP_LIBRARY}")
target_include_directories(pcap INTERFACE ${PCAP_INCLUDE_DIR})
