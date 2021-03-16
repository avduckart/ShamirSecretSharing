cmake_minimum_required(VERSION 3.12)

project(shamir_test)

#Setup gtest
set(GTEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/gtest/googletest)

if (USE_STATIC_RUNTIME_LINKAGE_FOR_WIN)
	set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
else()
	set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()
	
add_subdirectory(${GTEST_ROOT})

set(GTEST_HEADERS ${GTEST_ROOT}/include)
set(GTEST_LIBRARIES gtest gtest_main)

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
	${ProjectName})

target_include_directories(shamir_test PUBLIC 
	${OPENSSL_INCLUDE_DIR}
	${GTEST_HEADERS})

enable_testing()
add_test(test shamir_test)
