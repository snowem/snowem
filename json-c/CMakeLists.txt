#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.7)
cmake_policy(SET CMP0048 NEW)
project(json-c VERSION 0.13.99)


include(CheckSymbolExists)

check_symbol_exists(strtoll "stdlib.h" HAVE_STRTOLL)

set(cmake_strtoll "strtoll")
if (NOT HAVE_STRTOLL)
  # Use _strtoi64 if strtoll is not available.
  check_symbol_exists(_strtoi64 stdlib.h have_strtoi64)
  if (have_strtoi64)
    set(HAVE_STRTOLL 1)
    set(cmake_strtoll "_strtoi64")
    # could do the same for strtoull, if needed
  endif ()
endif ()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -D_GNU_SOURCE")
execute_process(COMMAND echo ${CMAKE_CURRENT_SOURCE_DIR} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)

set(JSON_C_PUBLIC_HEADERS
    ./json.h
    ./config.h
    ./json_config.h
    ./arraylist.h
    ./debug.h
    ./json_c_version.h
    ./json_inttypes.h
    ./json_object.h
    ./json_pointer.h
    ./json_tokener.h
    ./json_util.h
    ./linkhash.h
    ./printbuf.h
)
set(JSON_C_HEADERS
    ${JSON_C_PUBLIC_HEADERS}
    ./json_object_private.h
    ./random_seed.h
    ./strerror_override.h
    ./strerror_override_private.h
    ./math_compat.h
    ./snprintf_compat.h
    ./strdup_compat.h
    ./vasprintf_compat.h
)

set(JSON_C_SOURCES
    ./arraylist.c
    ./debug.c
    ./json_c_version.c
    ./json_object.c
    ./json_object_iterator.c
    ./json_pointer.c
    ./json_tokener.c
    ./json_util.c
    ./json_visit.c
    ./linkhash.c
    ./printbuf.c
    ./random_seed.c
    ./strerror_override.c
)

add_library(json-c
    SHARED
    ${JSON_C_SOURCES}
    ${JSON_C_HEADERS}
)

add_library(json-c-static
    STATIC
    ${JSON_C_SOURCES}
    ${JSON_C_HEADERS}
)

set_property(TARGET json-c PROPERTY C_STANDARD 99)
set_property(TARGET json-c-static PROPERTY C_STANDARD 99)
set_target_properties(json-c-static PROPERTIES OUTPUT_NAME json-c)

install(TARGETS json-c json-c-static
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${JSON_C_PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/json-c )

if (UNIX)
	set(prefix ${CMAKE_INSTALL_PREFIX})
	set(exec_prefix ${CMAKE_INSTALL_PREFIX}/bin)
	set(libdir ${CMAKE_INSTALL_PREFIX}/lib)
	set(includedir ${CMAKE_INSTALL_PREFIX}/include)
	set(VERSION ${PROJECT_VERSION})
	set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
	install(FILES ${CMAKE_BINARY_DIR}/json-c.pc DESTINATION "${INSTALL_PKGCONFIG_DIR}")
endif ()
