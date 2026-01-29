cmake_minimum_required (VERSION 4.2)
project ("Interop")

file(GLOB_RECURSE LIBOPAQUE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/noise_xk/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/liboprf/oprf/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/liboprf/oprf/aux_/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/libopaque/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/libopaque/utils/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/libopaque/aux_/*.c
)
list(FILTER LIBOPAQUE_SOURCES EXCLUDE REGEX "/tests/")
list(FILTER LIBOPAQUE_SOURCES EXCLUDE REGEX "/test/")
list(FILTER LIBOPAQUE_SOURCES EXCLUDE REGEX "/fuzz")
list(FILTER LIBOPAQUE_SOURCES EXCLUDE REGEX "/jni\\.c$")
add_library(libopaque STATIC ${LIBOPAQUE_SOURCES})

target_include_directories(libopaque PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/noise_xk/include
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/karmel
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/karmel/minimal
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/liboprf
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/liboprf/oprf
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/libopaque
)

if (WIN32)
  find_package(unofficial-sodium CONFIG REQUIRED)
  target_link_libraries(libopaque PRIVATE unofficial-sodium::sodium)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
  target_link_libraries(libopaque PRIVATE PkgConfig::SODIUM)
endif()



add_library(Interop SHARED 
    "Interop.c"
    "Interop.h"
    "OpaqueInterop.c"
    "OpaqueInterop.h"
)

target_link_libraries(Interop PRIVATE libopaque)

set_property(TARGET Interop PROPERTY CXX_STANDARD 20)
set_target_properties(Interop PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "../../Server"
)