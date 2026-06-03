cmake_minimum_required(VERSION 3.18)
project(raplt C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(RAPLT_STANDALONE "Build without STL dependencies" OFF)

add_library(raplt SHARED
    src/raplt_core.c
    src/raplt_elf.c
    src/raplt_hash.c
    src/raplt_signal.c
    src/raplt_util.c
    src/raplt_recon.c
    src/raplt_dlopen.c
    src/raplt_cfi.c
    src/raplt_jni.c
)

target_include_directories(raplt PUBLIC include)

target_compile_options(raplt PRIVATE
    -Wall -Wextra -Werror
    -fvisibility=hidden
    -Wno-unused-parameter
    -Wno-gnu-zero-variadic-macro-arguments
)

target_link_libraries(raplt PRIVATE log)

if(RAPLT_STANDALONE)
    target_compile_definitions(raplt PRIVATE RAPLT_STANDALONE)
    target_link_options(raplt PRIVATE -nostdlib)
endif()

set_target_properties(raplt PROPERTIES
    C_VISIBILITY_PRESET hidden
)

# Static library variant
add_library(raplt_static STATIC
    src/raplt_core.c
    src/raplt_elf.c
    src/raplt_hash.c
    src/raplt_signal.c
    src/raplt_util.c
    src/raplt_recon.c
)

target_include_directories(raplt_static PUBLIC include)
target_compile_options(raplt_static PRIVATE
    -Wall -Wextra -Werror
    -fvisibility=hidden
)
