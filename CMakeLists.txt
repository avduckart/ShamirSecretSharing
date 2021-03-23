cmake_minimum_required(VERSION 3.12)

# Project name
set(ProjectName shamir)
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

#hunter_add_package(OpenSSL)

find_package(OpenSSL REQUIRED)
if (NOT OpenSSL_FOUND)
	message(FATAL_ERROR "OpenSSL libraries not found! CMake will stop." )
else()
	set(OPENSSL_CRYPTO_LIBRARIES OpenSSL::Crypto)
	set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT}/include)
	message("Found OpenSSL libraries: ${OPENSSL_CRYPTO_LIBRARIES} " )
	message("Found OpenSSL includes: ${OPENSSL_INCLUDE_DIR}" )
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
add_test (test shamir_test)
