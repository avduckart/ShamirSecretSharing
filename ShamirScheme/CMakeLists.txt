cmake_minimum_required(VERSION 3.10)

add_library(${ProjectName} SHARED shamir_scheme.c) 

set_target_properties(${ProjectName}
  PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})
  
target_link_libraries(${ProjectName} 
    ${OPENSSL_CRYPTO_LIBRARIES} 
    ${CMAKE_DL_LIBS}
) 

target_include_directories(${ProjectName} PUBLIC
    ${OPENSSL_INCLUDE_DIR})

#install(TARGETS ${ProjectName} RUNTIME DESTINATION bin)
