cmake_minimum_required(VERSION 3.15)

project(ABCD VERSION 1.0 DESCRIPTION "A Binary C Disassembler")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(LibElf REQUIRED)

include_directories("include/")
include_directories("deps/args/")
include_directories(${LIBELF_INCLUDE_DIRS})

add_executable(abcd main.cpp abcd.cpp)
target_link_libraries(abcd PRIVATE "Zydis" elf)
target_compile_options(abcd PRIVATE ${DEFINES})
