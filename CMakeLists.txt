cmake_minimum_required(VERSION 3.16)
project(crypto_lab_1 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
add_compile_options(-Wall -Wextra)

add_library(util STATIC src/util.c)
target_include_directories(util PUBLIC include)

add_library(expmod STATIC src/expmod.c)
target_include_directories(expmod PUBLIC include)
target_link_libraries(expmod PUBLIC util)

add_library(invmod STATIC src/invmod.c)
target_include_directories(invmod PUBLIC include)
target_link_libraries(invmod PUBLIC expmod util)

add_library(logdis STATIC src/logdis.c)
target_include_directories(logdis PUBLIC include)
target_link_libraries(logdis PUBLIC invmod expmod util)

add_executable(crypto
        src/main.c
        src/vars.c
        src/csr.c
        src/csk.c
        src/vgn.c
        src/gf.c)
target_link_libraries(crypto PRIVATE logdis util)
