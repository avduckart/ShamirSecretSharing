cmake_minimum_required(VERSION 3.10)

add_library(${ProjectName} SHARED 
  shamir_scheme.c 
  calc.c) 

set_target_properties(${ProjectName}
  PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

  if (WIN32)
    set(WINSOCK ws2_32)
  endif()
  
target_link_libraries(${ProjectName} 
    ${OPENSSL_CRYPTO_LIBRARIES} 
    ${CMAKE_DL_LIBS}
    ${WINSOCK}
) 

target_include_directories(${ProjectName} PUBLIC
    ${PROJECT_INCLUDE_DIR} 
    ${OPENSSL_INCLUDE_DIR})

