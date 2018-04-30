## dependencies ###############################################################
# Find Libevent
# http://monkey.org/~provos/libevent/
#
# Once done, this will define:
#
#  Event_FOUND - system has Event
#  Event_INCLUDE_DIRS - the Event include directories
#  Event_LIBRARIES - link these to use Event
#

if (EVENT_INCLUDE_DIR AND EVENT_LIBRARY)
  # Already in cache, be silent
  set(EVENT_FIND_QUIETLY TRUE)
endif (EVENT_INCLUDE_DIR AND EVENT_LIBRARY)

find_path(EVENT_INCLUDE_DIR event.h
  PATHS /usr/include /usr/local/include
  PATH_SUFFIXES event2
)

find_library(EVENT_LIBRARY
  NAMES event
  PATHS /usr/lib /usr/local/lib
)

set(EVENT_INCLUDE_DIRS ${EVENT_INCLUDE_DIR})
set(EVENT_LIBRARIES ${EVENT_LIBRARY} )

add_definitions(-DLIBNET_LIL_ENDIAN)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(EVENT
  DEFAULT_MSG
  EVENT_INCLUDE_DIR
  EVENT_LIBRARIES
)
mark_as_advanced(EVENT_INCLUDE_DIR EVENT_LIBRARY)

find_path(EVENT_OPENSSL_INCLUDE_DIR bufferevent_ssl.h
  PATHS /usr/include /usr/local/include
  PATH_SUFFIXES event2
)

find_library(EVENT_OPENSSL_LIBRARY event_openssl)
set(EVENT_OPENSSL_LIBRARIES ${EVENT_OPENSSL_LIBRARY} )

find_package_handle_standard_args(EVENT_OPENSSL
  DEFAULT_MSG
  EVENT_OPENSSL_INCLUDE_DIR
  EVENT_OPENSSL_LIBRARIES
)

#find_library (LIBEVENT_OPENSSL event_openssl)
#if (NOT LIBEVENT_OPENSSL)
#   message(FATAL_ERROR "libevent_openssl not found, reinstall libevent with openssl")
#endif()


