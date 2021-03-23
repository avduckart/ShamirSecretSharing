cmake_minimum_required(VERSION 3.4)

include("gate/cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.23.224.tar.gz"
    SHA1 "18e57a43efc435f2e1dae1291e82e42afbf940be"
)

project(preload)

cmake_host_system_information(
  RESULT HUNTER_JOBS_NUMBER
  QUERY NUMBER_OF_LOGICAL_CORES
)

#hunter_add_package(GTest)
#hunter_add_package(OpenSSL)
