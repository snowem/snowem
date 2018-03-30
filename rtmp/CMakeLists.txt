cmake_minimum_required(VERSION 3.0) # setting this is required
project(rtmp)            # this sets the project name

include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

## file globbing ##############################################################
file(GLOB sources srs_librtmp.cpp rtmp.c log.c)

## target definitions #########################################################
add_library(rtmp ${sources})

# Just for example add some compiler flags.
target_compile_options(rtmp PUBLIC -g -Wall -O0 -lstdc++)

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(rtmp PUBLIC .)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindLibEvent.cmake)
if (${EVENT_FOUND})
   target_include_directories(rtmp PUBLIC ${EVENT_INCLUDE_DIRS})
   MESSAGE(STATUS "libevent include: ${EVENT_INCLUDE_DIRS}")
   MESSAGE(STATUS "libevent lib:  ${EVENT_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR EVENT not found)
endif ()

target_link_libraries(rtmp PUBLIC
  ${EVENT_LIBRARIES}
  ${EVENT_OPENSSL_LIBRARIES}
)


## packaging ##################################################################
# All install commands get the same destination. this allows us to use paths
# relative to the executable.
install(TARGETS rtmp DESTINATION bin)

# Now comes everything we need, to create a package
# there are a lot more variables you can set, and some
# you need to set for some package types, but we want to
# be minimal here.
set(CPACK_PACKAGE_NAME "rtmp")
set(CPACK_PACKAGE_VERSION "1.0.0")

# We don't want to split our program up into several incomplete pieces.
set(CPACK_MONOLITHIC_INSTALL 1)

# This must be last
include(CPack)

