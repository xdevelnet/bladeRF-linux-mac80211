cmake_minimum_required(VERSION 3.30)

project(bladeRF-linux-mac80211 C)

set(CMAKE_C_STANDARD 99)


find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED IMPORTED_TARGET libnl-genl-3.0 libbladeRF)

add_executable(bladeRF-linux-mac80211 bladeRF-linux-mac80211.c)

target_link_libraries(bladeRF-linux-mac80211 ${LIBNL_LINK_LIBRARIES})
target_include_directories(bladeRF-linux-mac80211 PUBLIC ${LIBNL_INCLUDE_DIRS})
