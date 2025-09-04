cmake_minimum_required(VERSION 2.8)

project(aes_cpp CXX)

option(AES_CPP_BUILD_TESTS "Build aes_cpp tests" OFF)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/aes.cpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/src/aes_utils.cpp)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(aes ${SOURCE_FILES})
add_library(aes_cpp::aes_cpp ALIAS aes)
add_library(aescpp ALIAS aes)
target_include_directories(aes PUBLIC ${INCLUDE_DIR})

if(AES_CPP_BUILD_TESTS)
  add_executable(tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.cpp)
  target_link_libraries(tests aes gtest pthread)
endif()
