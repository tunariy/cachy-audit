cmake_minimum_required(VERSION 3.21)
project(cachy-audit VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)

include(GNUInstallDirs)
install(TARGETS cachy-audit RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory(src)
