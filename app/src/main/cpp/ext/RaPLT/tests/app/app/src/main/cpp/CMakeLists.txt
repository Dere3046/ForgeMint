cmake_minimum_required(VERSION 3.18)
project(raplt_test C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# repo root relative to cpp/
set(RAPLT_ROOT ${CMAKE_SOURCE_DIR}/../../../../../..)

# raplt static lib
add_library(raplt STATIC
    ${RAPLT_ROOT}/src/raplt_core.c
    ${RAPLT_ROOT}/src/raplt_elf.c
    ${RAPLT_ROOT}/src/raplt_hash.c
    ${RAPLT_ROOT}/src/raplt_signal.c
    ${RAPLT_ROOT}/src/raplt_util.c
    ${RAPLT_ROOT}/src/raplt_recon.c
    ${RAPLT_ROOT}/src/raplt_dlopen.c
    ${RAPLT_ROOT}/src/raplt_cfi.c
    ${RAPLT_ROOT}/src/raplt_mremap.c
)
target_include_directories(raplt PUBLIC ${RAPLT_ROOT}/include)
target_compile_options(raplt PRIVATE -Wall -fvisibility=hidden -Wno-unused-parameter -Wno-unused-function)

add_library(calc SHARED calc_impl.c)
set_target_properties(calc PROPERTIES LINK_FLAGS "-Wl,-z,max-page-size=16384")

add_library(jni SHARED jni_bridge.c)
set_target_properties(jni PROPERTIES LINK_FLAGS "-Wl,-z,max-page-size=16384")
target_link_libraries(jni raplt calc log dl)
target_include_directories(jni PRIVATE ${RAPLT_ROOT}/include)
