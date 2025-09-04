cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "" FORCE)
  elseif(EXISTS "${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
    set(CMAKE_TOOLCHAIN_FILE
        "${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "" FORCE)
  else()
    find_program(VCPKG_EXEC vcpkg)
    if(VCPKG_EXEC)
      execute_process(COMMAND ${VCPKG_EXEC} integrate install)
    endif()
  endif()
endif()

project(aes_cpp CXX)

include(CMakePackageConfigHelpers)

set(AES_CPP_VERSION 0.1.0)

option(AES_CPP_BUILD_TESTS "Build aes_cpp tests" OFF)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/aes.cpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/src/aes_utils.cpp)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(aes ${SOURCE_FILES})
add_library(aes_cpp::aes_cpp ALIAS aes)
add_library(aescpp ALIAS aes)
target_include_directories(aes
  PUBLIC
    $<BUILD_INTERFACE:${INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)
set_target_properties(aes PROPERTIES EXPORT_NAME aes_cpp)

install(TARGETS aes EXPORT aes_cppTargets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

install(DIRECTORY include/ DESTINATION include)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/aes_cppConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/aes_cppConfig.cmake
  INSTALL_DESTINATION lib/cmake/aes_cpp
)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/aes_cppConfigVersion.cmake
  VERSION ${AES_CPP_VERSION}
  COMPATIBILITY AnyNewerVersion
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/aes_cppConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/aes_cppConfigVersion.cmake
  DESTINATION lib/cmake/aes_cpp
)

install(EXPORT aes_cppTargets
  FILE aes_cppTargets.cmake
  NAMESPACE aes_cpp::
  DESTINATION lib/cmake/aes_cpp
)

if(AES_CPP_BUILD_TESTS)
  add_executable(tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.cpp)
  target_link_libraries(tests aes gtest pthread)
endif()
