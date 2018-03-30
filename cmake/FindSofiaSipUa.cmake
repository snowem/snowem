############################################################################
#
# - Find the sofia-sip include file and library
#
#  SOFIASIPUA_FOUND - system has sofia-sip
#  SOFIASIPUA_INCLUDE_DIRS - the sofia-sip include directory
#  SOFIASIPUA_LIBRARIES - The libraries needed to use sofia-sip
#  SOFIASIPUA_CPPFLAGS - The cflags needed to use sofia-sip


set(_SOFIASIPUA_HINT_PATHS
	${WITH_SOFIASIPUA}
	${CMAKE_INSTALL_PREFIX}
	)

find_path(SOFIASIPUA_INCLUDE_DIR
	NAMES sofia-sip/sip.h
	HINTS _SOFIASIPUA_HINT_PATHS
	PATH_SUFFIXES include/sofia-sip-1.13 include/sofia-sip-1.12
	)

if(SOFIASIPUA_INCLUDE_DIR)
	set(HAVE_SOFIASIPUA_SOFIASIPUA_H 1)

	file(STRINGS "${SOFIASIPUA_INCLUDE_DIR}/sofia-sip/sofia_features.h" SOFIASIPUA_VERSION_STR
		REGEX "^#define[\t ]+SOFIA_SIP_VERSION[\t ]+\"([0-9a-zA-Z.])+\"$")

	string(REGEX REPLACE "^.*SOFIA_SIP_VERSION[\t ]+\"([0-9a-zA-Z.]+)\"$"
		   "\\1" SOFIASIPUA_VERSION "${SOFIASIPUA_VERSION_STR}")
endif()

find_library(SOFIASIPUA_LIBRARIES
	NAMES sofia-sip-ua
	HINTS ${_SOFIASIPUA_HINT_PATHS}
	PATH_SUFFIXES bin lib
	)

#list(REMOVE_DUPLICATES SOFIASIPUA_INCLUDE_DIRS)
#list(REMOVE_DUPLICATES SOFIASIPUA_LIBRARIES)
#set(SOFIASIPUA_CPPFLAGS "")

include(FindPackageHandleStandardArgs)


if (SOFIASIPUA_VERSION)
	find_package_handle_standard_args(SofiaSipUa
		REQUIRED_VARS SOFIASIPUA_INCLUDE_DIR SOFIASIPUA_LIBRARIES
		VERSION_VAR SOFIASIPUA_VERSION
		)
else()
	find_package_handle_standard_args(SofiaSipUa
		REQUIRED_VARS SOFIASIPUA_INCLUDE_DIR SOFIASIPUA_LIBRARIES
		)
endif()

mark_as_advanced(SOFIASIPUA_INCLUDE_DIR SOFIASIPUA_LIBRARIES SOFIASIPUA_CPPFLAGS)
