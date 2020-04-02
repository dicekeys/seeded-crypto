file(GLOB SRCS
    "*.h"
    "*/*.h"
    "*.cpp"
    "*/*.cpp"
)

# This if statement is a hack until Stuart figures out
# how to get builds with shared libs working on windows
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
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
