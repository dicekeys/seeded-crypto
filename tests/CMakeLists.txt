message("Entered: Tests")

include(GoogleTest)

# See: https://cliutils.gitlab.io/modern-cmake/chapters/testing/googletest.html#fn_1

# For Visual Studio on Windows, we'll get linker errors if we don't
# force GoogleTest to use dynamic c library.  See:
# https://github.com/google/googletest/blob/master/googletest/README.md
#   Look for the section titled "Visual Studio Dynamic vs Static Runtimes"
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Now bring in the Google Test subdirectory.
# How did it get here?  We used:
# > git submodule add https://github.com/google/googletest.git extern/googletest
add_subdirectory("${PROJECT_SOURCE_DIR}/extern/googletest" "extern/googletest")

include_directories(
  ${SEEDED_PROJECT_DIR}/extern/googletest/googletest/include
)

mark_as_advanced(
    BUILD_GMOCK BUILD_GTEST BUILD_SHARED_LIBS
    gmock_build_tests gtest_build_samples gtest_build_tests
    gtest_disable_pthreads gtest_force_shared_crt gtest_hide_internal_symbols
)

set_target_properties(gtest PROPERTIES FOLDER extern)
set_target_properties(gtest_main PROPERTIES FOLDER extern)
set_target_properties(gmock PROPERTIES FOLDER extern)
set_target_properties(gmock_main PROPERTIES FOLDER extern)

macro(package_add_test TESTNAME FILES LIBRARIES)
    message("Addiing test >${TESTNAME}<  files: ${FILES}  libraries: ${LIBRARIES} working_directory: ${SEEDED_PROJECT_DIR}")
    
    add_executable("${TESTNAME}" "${FILES}")
    target_link_libraries(
        ${TESTNAME}
        PRIVATE
        gtest
        gmock
        gtest_main
        "${LIBRARIES}"
    )
    set_target_properties(${TESTNAME} PROPERTIES FOLDER tests)
    set_target_properties(${TESTNAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    set_target_properties(${TESTNAME} PROPERTIES CXX_STANDARD 11)
    # set_target_properties(${TESTNAME} PROPERTIES ENVIRONMENT "TEST_DIR=${SEEDED_PROJECT_DIR}")
    set_target_properties(${TESTNAME} PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${SEEDED_PROJECT_DIR}")
    gtest_discover_tests(${TESTNAME}
        WORKING_DIRECTORY ${SEEDED_PROJECT_DIR}
        PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${SEEDED_PROJECT_DIR}"
    )
endmacro()


###################################
# Add test subdirectories
###################################
add_subdirectory(
    test-seeded
)