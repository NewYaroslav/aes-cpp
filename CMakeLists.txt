cmake_minimum_required(VERSION 3.14)

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

project(aes_cpp VERSION 0.2.1 LANGUAGES CXX)
enable_testing()

include(CheckSymbolExists)
include(CMakePackageConfigHelpers)

set(AES_CPP_VERSION 0.2.1)

option(AES_CPP_BUILD_TESTS "Build aes_cpp tests" OFF)
option(AES_CPP_ENABLE_AESNI "Build AES-NI/PCLMUL code paths" ON)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/aes.cpp
                 ${CMAKE_CURRENT_SOURCE_DIR}/src/aes_utils.cpp)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

check_symbol_exists(explicit_bzero "string.h" HAVE_EXPLICIT_BZERO)

add_library(aes_cpp ${SOURCE_FILES})
target_compile_features(aes_cpp PUBLIC cxx_std_11)
add_library(aes_cpp::aes_cpp ALIAS aes_cpp)
add_library(aescpp ALIAS aes_cpp)
target_include_directories(aes_cpp
  PUBLIC
    $<BUILD_INTERFACE:${INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)
set_target_properties(aes_cpp PROPERTIES EXPORT_NAME aes_cpp)

if(HAVE_EXPLICIT_BZERO)
  target_compile_definitions(aes_cpp PUBLIC HAVE_EXPLICIT_BZERO)
endif()

if(AES_CPP_ENABLE_AESNI
   AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"
   AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i.86")
  target_compile_options(aes_cpp PRIVATE -maes -mpclmul -msse2 -mssse3)
endif()

install(TARGETS aes_cpp EXPORT aes_cppTargets
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
  find_package(GTest CONFIG)
  if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG v1.14.0
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(googletest)
  endif()
  find_package(Threads REQUIRED)
  add_executable(tests ${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.cpp)
  target_link_libraries(tests aes_cpp GTest::gtest Threads::Threads)
  add_test(NAME aes_cpp_tests COMMAND tests)
endif()
