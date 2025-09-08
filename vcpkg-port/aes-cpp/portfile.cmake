set(AES_CPP_BUILD_TESTS OFF)
if("tests" IN_LIST FEATURES)
    set(AES_CPP_BUILD_TESTS ON)
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${CURRENT_PORT_DIR}/../.."
    OPTIONS
        -DAES_CPP_BUILD_TESTS=${AES_CPP_BUILD_TESTS}
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/aes_cpp)
