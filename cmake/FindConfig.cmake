# CONFIG_INCLUDE_DIRS - where to find <nettle/sha.h>, etc.
# CONFIG_LIBRARIES - List of libraries when using libnettle.
# CONFIG_FOUND - True if libnettle found.
if(CONFIG_INCLUDE_DIRS)
	# Already in cache, be silent
	set(CONFIG_FIND_QUIETLY YES)
endif()

find_path(CONFIG_INCLUDE_DIRS libconfig.h)
find_library(CONFIG_LIBRARY NAMES config libconfig)

# handle the QUIETLY and REQUIRED arguments and set CONFIG_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CONFIG DEFAULT_MSG CONFIG_LIBRARY CONFIG_INCLUDE_DIRS)

if(CONFIG_FOUND)
	set(CONFIG_LIBRARIES ${CONFIG_LIBRARY})
endif()
