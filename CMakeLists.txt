cmake_minimum_required(VERSION 3.23)

set(PROJECT "JwtLicensing")

project("${PROJECT}_Project" VERSION 1.2.3 LANGUAGES CXX)

# Global CMake variables are set here
set(CMAKE_CXX_STANDARD          20) #20)# hat er irgendwie noch nicht
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)


# Cmake modules
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/)





# Project/Library Names
set(MAIN            "${PROJECT}_Executable")


# boost jwt-cpp stuff needs openssl
find_package(OpenSSL REQUIRED)
if (${OpenSSL_FOUND})
    message(${OPENSSL_INCLUDE_DIR})
    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
endif ()

# Add external libraries
add_subdirectory("${PROJECT_SOURCE_DIR}/external/")


# Add executables
add_subdirectory("${PROJECT_SOURCE_DIR}/app/")




