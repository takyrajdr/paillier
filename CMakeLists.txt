# ------------------------------------------------------------------------------
#   Project settings
#
cmake_minimum_required(VERSION 3.5)
#~ cmake_minimum_required(VERSION 2.8)
project(paillier C)
set (paillier_VERSION_MAJOR 0)
set (paillier_VERSION_MINOR 9)
set (paillier_VERSION_PATCH 1)


# ------------------------------------------------------------------------------
#   Setup output folders
#
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../lib)
#~ set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)


# ------------------------------------------------------------------------------
#   Compiler flags
#
#~ set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ansi -Wall -pedantic")


# ------------------------------------------------------------------------------
#   Add subdirs
#
add_subdirectory(src)
add_subdirectory(examples)
