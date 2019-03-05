cmake_minimum_required (VERSION 2.6)
project (pparser)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -O0")

add_executable(pparser read.cpp)

link_directories(/usr/local/lib)
target_link_libraries (pparser pcap)
