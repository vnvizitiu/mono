cmake_minimum_required (VERSION 2.8.10)

project (mono-btls)

# cmake_policy(SET CMP0026 OLD)

add_subdirectory (${BTLS_ROOT} boringssl)
set (CMAKE_MACOSX_RPATH 1)

# SET (CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib)
# SET (CMAKE_SKIP_BUILD_RPATH FALSE)
# SET (CMAKE_BUILD_WITH_INSTALL_RPATH TRUE) 

include_directories (
	${SRC_DIR}
	${BTLS_ROOT}/include
)

set (
	MONO_BTLS_SOURCES

	btls-bio.c
	btls-bio.h
	btls-key.c
	btls-key.h
	btls-pkcs12.c
	btls-pkcs12.h
	btls-ssl-ctx.c
	btls-ssl-ctx.h
	btls-ssl.c
	btls-ssl.h
	btls-util.c
	btls-util.h
	btls-x509-chain.c
	btls-x509-chain.h
	btls-x509-crl.c
	btls-x509-crl.h
	btls-x509-lookup-method.c
	btls-x509-lookup-method.h
	btls-x509-lookup.c
	btls-x509-lookup.h
	btls-x509-name.c
	btls-x509-name.h
	btls-x509-revoked.c
	btls-x509-revoked.h
	btls-x509-store-ctx.c
	btls-x509-store-ctx.h
	btls-x509-store.c
	btls-x509-store.h
	btls-x509-verify-param.c
	btls-x509-verify-param.h
	btls-x509.c
	btls-x509.h

	btls-android-utils.c

	${BORINGSSL_OBJECTS}
)

if (BUILD_SHARED_LIBS)
	add_library (mono-btls-shared SHARED ${MONO_BTLS_SOURCES})
	set_target_properties (mono-btls-shared PROPERTIES RULE_LAUNCH_LINK
		"${PROJECT_SOURCE_DIR}/create-object-library.sh ${CMAKE_BINARY_DIR} libmono-btls-objects.a <OBJECTS> --"
	)
	install (
		TARGETS mono-btls-shared
		LIBRARY DESTINATION lib
	)
else ()
	add_library (mono-btls-static STATIC ${MONO_BTLS_SOURCES})
	install (
		TARGETS mono-btls-static
		ARCHIVE DESTINATION lib
	)
endif ()

include (CMakeMacros.txt)

if (BUILD_SHARED_LIBS)
	create_libtool (mono-btls-shared ${PROJECT_SOURCE_DIR}/libmono-btls.la.in true false mono-btls-shared mono-btls-static ${PROJECT_BINARY_DIR})
	install (
		FILES ${PROJECT_BINARY_DIR}/libmono-btls-shared.la
		DESTINATION lib
	)
else ()
	create_libtool (mono-btls-static ${PROJECT_SOURCE_DIR}/libmono-btls.la.in false true mono-btls-shared mono-btls-static ${PROJECT_BINARY_DIR})
endif ()

