# BSD_INCLUDE_DIRS - where to find <nettle/sha.h>, etc.
# BSD_LIBRARIES - List of libraries when using libnettle.
# BSD_FOUND - True if libnettle found.
if(BSD_INCLUDE_DIRS)
	# Already in cache, be silent
	set(BSD_FIND_QUIETLY YES)
endif()

find_path(BSD_INCLUDE_DIRS bsd/bsd.h)
find_library(BSD_LIBRARY NAMES bsd libbsd)

# handle the QUIETLY and REQUIRED arguments and set BSD_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BSD DEFAULT_MSG BSD_LIBRARY BSD_INCLUDE_DIRS)

if(BSD_FOUND)
	set(BSD_LIBRARIES ${BSD_LIBRARY})
endif()
