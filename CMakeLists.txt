cmake_minimum_required(VERSION 3.0) # setting this is required
project(snowem)            # this sets the project name

include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

add_subdirectory(cice EXCLUDE_FROM_ALL)
add_subdirectory(wslay EXCLUDE_FROM_ALL)
add_subdirectory(json-c EXCLUDE_FROM_ALL)
#add_subdirectory(rtmp EXCLUDE_FROM_ALL)

configure_file( core/config.in.h ${CMAKE_BINARY_DIR}/generated/config.h )
include_directories( ${CMAKE_BINARY_DIR}/generated/ )

if ("${CMAKE_PREFIX_PATH}" STREQUAL "")
  set(SNOWEM_PREFIX_PATH "/var/snowem")
else()
  set(SNOWEM_PREFIX_PATH "${CMAKE_PREFIX_PATH}")
endif()
add_definitions( -DSNOWEM_PREFIX_PATH=${SNOWEM_PREFIX_PATH} )

execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  RESULT_VARIABLE GIT_BRANCH_RESULT
  ERROR_VARIABLE GIT_BRANCH_ERROR
  OUTPUT_VARIABLE GIT_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

MESSAGE(STATUS "git branch result: ${GIT_BRANCH_RESULT}")
if ( ${GIT_BRANCH_RESULT} EQUAL 0 )
  MESSAGE(STATUS "git branch: ${GIT_BRANCH}")
  add_definitions("-DGIT_BRANCH=${GIT_BRANCH}")
else ()
  MESSAGE(STATUS "unknown git branch")
  add_definitions("-DGIT_BRANCH=unknown")
endif()

execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  RESULT_VARIABLE GIT_COMMIT_RESULT
  ERROR_VARIABLE GIT_COMMIT_ERROR
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

MESSAGE(STATUS "git commit result: ${GIT_COMMIT_RESULT}")
if ( ${GIT_COMMIT_RESULT} EQUAL 0 )
  MESSAGE(STATUS "git COMMIT: ${GIT_COMMIT_HASH}")
  add_definitions("-DGIT_COMMIT_HASH=${GIT_COMMIT_HASH}")
else ()
  MESSAGE(STATUS "unknown git COMMIT")
  add_definitions("-DGIT_COMMIT_HASH=unknown")
endif()

## file globbing ##############################################################
file(GLOB sources
       core/*.c core/*.cpp core/*.h
       ice/*.c ice/*.h
       websocket/*.c websocket/*.h
       http/*.c http/*.h
       rtp/*.c rtp/*.h
       recording/*.c recording/*.h
       )
file(GLOB c_sources core/*.c ice/*.c websocket/*.c)

## target definitions #########################################################
add_executable(snowem ${sources})

target_compile_options(snowem PUBLIC -std=gnu99)
target_include_directories(snowem PUBLIC .)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindDL.cmake)
if (${DL_FOUND})
   target_include_directories(snowem PUBLIC ${DL_INCLUDE_DIRS})
   MESSAGE(STATUS "dl include: ${DL_INCLUDE_DIRS}")
   MESSAGE(STATUS "dl lib: ${DL_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR "DL not found")
endif ()

find_package(OpenSSL)
if (${OPENSSL_FOUND})
   target_include_directories(snowem PUBLIC ${OPENSSL_INCLUDE_DIR})
else (${OPENSSL_FOUND})
   MESSAGE(FATAL_ERROR "OpenSSL not found")
endif (${OPENSSL_FOUND})

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindLibEvent.cmake)
if (${EVENT_FOUND})
   target_include_directories(snowem PUBLIC ${EVENT_INCLUDE_DIRS})
   MESSAGE(STATUS "libevent include: ${EVENT_INCLUDE_DIRS}")
   MESSAGE(STATUS "libevent lib:  ${EVENT_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR EVENT not found)
endif ()


include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindSofiaSipUa.cmake)
if (${SOFIASIPUA_FOUND})
   target_include_directories(snowem PUBLIC ${SOFIASIPUA_INCLUDE_DIR})
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SOFIASIPUA_CPPFLAGS}")
else (${SOFIASIPUA_FOUND})
   MESSAGE(FATAL_ERROR SofiaSipUa Not Found)
endif (${SOFIASIPUA_FOUND})


include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindSRTP.cmake)
if (${SRTP_FOUND})
   target_include_directories(snowem PUBLIC ${SRTP_INCLUDE_DIRS})
   MESSAGE(STATUS "srtp include: ${SRTP_INCLUDE_DIRS}")
   MESSAGE(STATUS "srtp lib: ${SRTP_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR SRTP not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindNettle.cmake)
if (${NETTLE_FOUND})
   target_include_directories(snowem PUBLIC ${NETTLE_INCLUDE_DIRS})
   MESSAGE(STATUS "nettle include: ${NETTLE_INCLUDE_DIRS}")
   MESSAGE(STATUS "nettle lib: ${NETTLE_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR NETTLE not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindConfig.cmake)
if (${CONFIG_FOUND})
   target_include_directories(snowem PUBLIC ${CONFIG_INCLUDE_DIRS})
   MESSAGE(STATUS "libconfig include: ${CONFIG_INCLUDE_DIRS}")
   MESSAGE(STATUS "libconfig lib: ${CONFIG_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR LIBCONFIG not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindBSD.cmake)
if (${BSD_FOUND})
   target_include_directories(snowem PUBLIC ${BSD_INCLUDE_DIRS})
   MESSAGE(STATUS "libbsd include: ${BSD_INCLUDE_DIRS}")
   MESSAGE(STATUS "libbsd lib: ${BSD_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR LIBBSD not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindLibM.cmake)
if (${LIBM_FOUND})
   target_include_directories(snowem PUBLIC ${LIBM_INCLUDE_DIR})
   MESSAGE(STATUS "libm include: ${LIBM_INCLUDE_DIR}")
   MESSAGE(STATUS "libm lib: ${LIBM_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR LIBM not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindFFmpeg.cmake)
if (${FFMPEG_FOUND})
  target_include_directories(snowem PUBLIC ${FFMPEG_INCLUDE_DIR})
  MESSAGE(STATUS "ffmpeg include: ${FFMPEG_INCLUDE_DIR}")
  MESSAGE(STATUS "ffmpeg lib: ${FFMPEG_LIBRARIES}")
else ()
  MESSAGE(FATAL_ERROR "FFMPEG not found")
endif ()



target_link_libraries(snowem PUBLIC
  cice_static
  wslay
  json-c
  #rtmp
  ${DL_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${EVENT_LIBRARIES}
  ${EVENT_OPENSSL_LIBRARIES}
  ${SOFIASIPUA_LIBRARIES}
  ${SRTP_LIBRARIES}
  ${NETTLE_LIBRARIES}
  ${CONFIG_LIBRARIES}
  ${BSD_LIBRARIES}
  ${LIBM_LIBRARIES}
  ${FFMPEG_LIBRARIES}
)

## packaging ##################################################################
MESSAGE(STATUS "install: ${SNOWEM_PREFIX_PATH}")
set(HTML_SNOWEM_DIR ${SNOWEM_PREFIX_PATH}/html)
set(DATA_SNOWEM_DIR ${SNOWEM_PREFIX_PATH}/data)
set(LOG_SNOWEM_DIR /var/log/snowem)
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${SNOWEM_PREFIX_PATH})")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${HTML_SNOWEM_DIR})")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${DATA_SNOWEM_DIR})")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${LOG_SNOWEM_DIR})")
install(FILES conf/snowem.conf conf/example.crt conf/example.key DESTINATION ${SNOWEM_PREFIX_PATH})
install(FILES html/index.html html/js/snowsdk.js html/js/adapter.js html/js/app.js DESTINATION ${HTML_SNOWEM_DIR})
install(TARGETS snowem DESTINATION /usr/local/bin)

set(CPACK_PACKAGE_NAME "snowem")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)

