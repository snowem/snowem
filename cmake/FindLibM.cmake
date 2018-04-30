# This CMake module defines the following variables:
#  LIBM_FOUND        =  Libraries and headers found; TRUE/FALSE
#  LIBM_INCLUDE_DIR     =  Path to the LIBM header files
#  LIBM_LIBRARIES    =  Path to all parts of the LIBM libraries
#  LIBM_LIBRARY_DIR  =  Path to the directory containing the LIBM libraries

# Check for the header files:
find_path( LIBM_INCLUDE_DIR
  NAMES math.h
  HINTS /usr/include /usr/local/include
  PATH_SUFFIXES
)

# Check for the libraries:
set( LIBM_LIBRARIES "" )

find_library( LIBM_LIBRARY
  NAMES m
  HINTS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu /usr/lib/i386-linux-gnu
  #PATH_SUFFIXES 
  NO_DEFAULT_PATH
)

# Libraries found?
if( LIBM_LIBRARY )
  list( APPEND LIBM_LIBRARIES ${LIBM_LIBRARY} )
  get_filename_component( LIBM_LIBRARY_DIR ${LIBM_LIBRARY} PATH )
endif( LIBM_LIBRARY )

# Headers AND libraries found?
if( LIBM_INCLUDE_DIR AND LIBM_LIBRARIES )
  set( LIBM_FOUND TRUE )
else( LIBM_INCLUDE_DIR AND LIBM_LIBRARIES )
  set( LIBM_FOUND FALSE )
  if( NOT LIBM_FIND_QUIETLY )
    if( NOT LIBM_INCLUDE_DIR )
      message( WARNING "Unable to find LIBM header files!" )
    endif( NOT LIBM_INCLUDE_DIR )
    if( NOT LIBM_LIBRARIES )
      message( WARNING "Unable to find LIBM library files!" )
    endif( NOT LIBM_LIBRARIES )
  endif( NOT LIBM_FIND_QUIETLY )
endif( LIBM_INCLUDE_DIR AND LIBM_LIBRARIES )

# Headers AND libraries found!
if( LIBM_FOUND )
  if( NOT LIBM_FIND_QUIETLY )
    message( STATUS "Found LIBM: ${LIBM_LIBRARIES}" )
  endif( NOT LIBM_FIND_QUIETLY )
else( LIBM_FOUND )
  if( LIBM_FIND_REQUIRED )
    message( FATAL_ERROR "Could not find LIBM headers or libraries!" )
  endif( LIBM_FIND_REQUIRED )
endif( LIBM_FOUND )

# Mark as advanced options in ccmake:
mark_as_advanced( 
  LIBM_INCLUDE_DIR
  LIBM_LIBRARIES
  LIBM_LIBRARY
  LIBM_LIBRARY_DIR
)

