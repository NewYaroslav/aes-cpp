cmake_minimum_required(VERSION 2.8)

project(AES CXX)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/aes.cpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/src/aes_utils.cpp)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(${PROJECT_NAME} ${SOURCE_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})

add_executable(tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.cpp)
target_link_libraries(tests ${PROJECT_NAME} gtest pthread)
