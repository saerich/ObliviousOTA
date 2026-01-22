cmake_minimum_required (VERSION 4.2)
project ("Interop")

file(GLOB_RECURSE LIBOPAQUE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/**/*.c
)
add_library(libopaque STATIC ${LIBOPAQUE_SOURCES})

target_include_directories(libopaque PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/karmel
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/libopaque
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/noise_xk
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/liboprf
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
set_property(TARGET Interop PROPERTY CXX_STANDARD 20)
set_target_properties(Interop PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "../../Server"
)