file(GLOB SRCS
    "*.h"
    "*/*.h"
    "*.hpp"
    "*/*.hpp"
    "*.cpp"
    "*/*.cpp"
)

# This if statement is a hack until Stuart figures out
# how to get builds with shared libs working on windows
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
    add_library(lib-seeded
        STATIC
        ${SRCS}
    )
else()
    add_library(lib-seeded
        SHARED
        ${SRCS}
    )
endif()

target_link_libraries(lib-seeded
    PRIVATE
        sodium
)

# Use C++ 11
set_target_properties(lib-seeded PROPERTIES
	CXX_STANDARD 11
)
