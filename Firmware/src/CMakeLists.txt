# This file was automatically generated for projects
# without default 'CMakeLists.txt' file.

FILE(GLOB_RECURSE app_sources 
    ${CMAKE_SOURCE_DIR}/src/*.c
    ${CMAKE_SOURCE_DIR}/lib/*.c
    ${CMAKE_SOURCE_DIR}/../Interop/Interop.c
    ${CMAKE_SOURCE_DIR}/../Interop/OpaqueInterop.c
    ${CMAKE_SOURCE_DIR}/../Interop/OPRFInterop.c
)

idf_component_register(
    SRCS ${app_sources}
)