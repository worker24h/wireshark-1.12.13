# - Try to find GThread2
#
# Find GThread headers, libraries and the answer to all questions.
#
#  GTHREAD2_FOUND               True if GTHREAD2 got found
#  GTHREAD2_INCLUDE_DIRS        Location of GTHREAD2 headers
#  GTHREAD2_LIBRARIES           List of libraries to use GTHREAD2
#
#  Copyright (c) 2008 Bjoern Ricks <bjoern.ricks@googlemail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

include( FindPkgConfig )

if( GTHREAD2_FIND_REQUIRED )
	set( _pkgconfig_REQUIRED "REQUIRED" )
else()
	set( _pkgconfig_REQUIRED "" )
endif()

if( GTHREAD2_MIN_VERSION )
	PKG_SEARCH_MODULE( GTHREAD2 ${_pkgconfig_REQUIRED} gthread-2.0>=${GTHREAD2_MIN_VERSION} )
else()
	PKG_SEARCH_MODULE( GTHREAD2 ${_pkgconfig_REQUIRED} gthread-2.0 )
endif()

if( NOT GTHREAD2_FOUND )
	include( FindWSWinLibs )
	if( BUILD_wireshark )
		if( ENABLE_GTK3 )
			FindWSWinLibs( "gtk3" "GTHREAD2_HINTS" )
		else()
			FindWSWinLibs( "gtk2" "GTHREAD2_HINTS" )
		endif()
	else()
		message( ERROR "Unsupported build setup" )
	endif()
	find_path( GTHREAD2_INCLUDE_DIRS gthread.h PATH_SUFFIXES glib-2.0 glib GLib.framework/Headers/glib glib-2.0/glib HINTS "${GTHREAD2_HINTS}/include" )
	if( APPLE )
		find_library( GTHREAD2_LIBRARIES glib )
	else()
		find_library( GTHREAD2_LIBRARIES gthread-2.0 HINTS "${GTHREAD2_HINTS}/lib" )
	endif()
	include( FindPackageHandleStandardArgs )
	find_package_handle_standard_args( GTHREAD2 DEFAULT_MSG GTHREAD2_LIBRARIES GTHREAD2_INCLUDE_DIRS )
endif()

mark_as_advanced( GTHREAD2_LIBRARIES GTHREAD2_INCLUDE_DIRS )
