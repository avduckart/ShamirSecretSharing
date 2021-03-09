cmake_minimum_required(VERSION 3.10)

# Project name
set(ProjectName shamir_scheme)
project(${ProjectName})

set(BUILD_SUB_DIR $<IF:$<CONFIG:Debug>,Debug,Release>) 
set(BUILD_DIR 
	${CMAKE_SOURCE_DIR}/build/${BUILD_SUB_DIR}
)

option(USE_STATIC_RUNTIME_LINKAGE "" ON)

if (WIN32)

	if (USE_STATIC_RUNTIME_LINKAGE)
		set(MSVC_LINKAGE MT)	
	else()
		set(MSVC_LINKAGE MD)
	endif()

	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /bigobj /${MSVC_LINKAGE}d")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /O2 /${MSVC_LINKAGE}d")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /${MSVC_LINKAGE}")
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /bigobj /${MSVC_LINKAGE}d")
	set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} /O2 /${MSVC_LINKAGE}d")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /${MSVC_LINKAGE}")
endif()

if (WIN32)
	find_package(OPENSSL) 
	if (NOT OPENSSL_FOUND)
		message(FATAL_ERROR "OpenSSL not found! CMake will stop." )
	endif()
	message("Found OpenSSL libraries: ${OPENSSL_CRYPTO_LIBRARIES} " )
	message("Found OpenSSL includes: ${OPENSSL_INCLUDE_DIR}" )
else()
	set(OPENSSL_CRYPTO_LIBRARIES shamir_scheme)
	set(OPENSSL_INCLUDE_DIR "/usr/include/openssl")
endif()

add_subdirectory(ShamirScheme)
add_subdirectory(testing)

#CPack
set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_CONTACT avduckart@gmail.com)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
include(CPack)

#tests
enable_testing()
add_test (shamir_test shamir_test)