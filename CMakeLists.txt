cmake_minimum_required(VERSION 3.16)
project(crypto_lab_1 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# без явного типа сборки - Release, иначе -BENCH меряет код без оптимизации
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

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

# примеры 3.5.1-3.5.3 из методички, собираются как есть
foreach(example expmod_orig invmod_orig logdis_orig)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/examples/${example}.c)
        add_executable(${example} examples/${example}.c)
    endif()
endforeach()
