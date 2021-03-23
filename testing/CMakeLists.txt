cmake_minimum_required(VERSION 3.12)

project(shamir_test)

if (WIN32)

	set(MSVC_LINKAGE MD)

	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /bigobj /${MSVC_LINKAGE}d")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /O2 /${MSVC_LINKAGE}d")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /${MSVC_LINKAGE}")
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /bigobj /${MSVC_LINKAGE}d")
	set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} /O2 /${MSVC_LINKAGE}d")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /${MSVC_LINKAGE}")
endif()

#hunter_add_package(GTest)

find_package(GTest CONFIG REQUIRED)
if (NOT GTest_FOUND)
	message(FATAL_ERROR "GTest libraries not found! CMake will stop." )
else()
	set(GTEST_LIBRARIES GTest::gtest_main GTest::gtest)
	set(GTEST_INCLUDE_DIR ${GTEST_ROOT}/include)
	message("Found GTest libraries: ${GTEST_LIBRARIES} " )
	message("Found GTest includes: ${GTEST_INCLUDE_DIR}" )
endif()

	
add_executable(shamir_test main.cpp)

set_target_properties(shamir_test
	PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

target_link_libraries(shamir_test PRIVATE 
	${GTEST_LIBRARIES} 
	${OPENSSL_CRYPTO_LIBRARIES} 
	${CMAKE_DL_LIBS}
	${ProjectName}
)

target_include_directories(shamir_test PUBLIC 
	${OPENSSL_INCLUDE_DIR}
	${GTEST_INCLUDE_DIR})
