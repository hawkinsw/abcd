cmake_minimum_required(VERSION 3.15)

project(ABCD VERSION 1.0 DESCRIPTION "A Binary C Disassembler")

set(CMAKE_C_STANDARD 11)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

include_directories("include/")
include_directories("deps/args/")

add_executable(abcd abcd.cpp)
target_link_libraries(abcd PRIVATE "Zydis")
target_compile_options(abcd PRIVATE ${DEFINES})
