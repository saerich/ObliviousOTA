cmake_minimum_required (VERSION 4.2)
project ("Interop")
add_library(Interop SHARED 
    "Interop.c"
    "Interop.h"
)
set_property(TARGET Interop PROPERTY CXX_STANDARD 20)
set_target_properties(Interop PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "../../Server"
)