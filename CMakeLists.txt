cmake_minimum_required(VERSION 3.10)

### Hunter snapshot that will be used ###
include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.23.224.tar.gz"
    SHA1 "18e57a43efc435f2e1dae1291e82e42afbf940be"
)

# Project name
set(ProjectName shamir)
project(${ProjectName} VERSION 0.0.1)

set(BUILD_SUB_DIR $<IF:$<CONFIG:Debug>,Debug,Release>) 
set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build/${BUILD_SUB_DIR})
set(PROJECT_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/headers)

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
else()
	set(GCC_COVERAGE_COMPILE_FLAGS "-g -O0 -coverage -fprofile-arcs -ftest-coverage")
endif()

hunter_add_package(OpenSSL)

find_package(OpenSSL REQUIRED)
if (NOT OpenSSL_FOUND)
	message(FATAL_ERROR "OpenSSL libraries not found! CMake will stop." )
else()
	set(OPENSSL_CRYPTO_LIBRARIES OpenSSL::Crypto)
	set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT}/include)
endif()

add_subdirectory(source)
add_subdirectory(testing)


enable_testing()
add_test (test ${BUILD_DIR}/shamir_test)
