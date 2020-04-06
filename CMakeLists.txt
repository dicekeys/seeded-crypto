#######################################################################
# IMPORTANT SHORTCOMINGS OF THIS CMAKE CONFIG FOR VISUAL STUDIO USERS
#
# Visual Studio unfortunatly defaults to overriding the working directory
# for Google Test set by CMAKE.
# To fix this
#    go to Visual Studio's debug menu or tool menu,
#    choose the "options" item, and then
#    go to the "Test Adapter For GoogleTest" tab.
#   Set 'Working Directory' to '$(SolutionDir)'
#   (note, those are parens around SolutionDir, and not braces
#    as one might become accustomed to seeing in CMake).
#
#######################################################################
message("
*********************************************************************
 IMPORTANT SHORTCOMINGS OF THIS CMAKE CONFIG FOR VISUAL STUDIO USERS
*********************************************************************

CMake fails to configure the working directory for running
tests in Visual Studio using Google Test.
Before running, got to Visual Studio's debug menu,
choose the 'options' item, and then go to the

'TestAdapterForGoogleTest' tab.
Set 'Working Directory' to '$(SolutionDir)'
(note, those are parens around SolutionDir, and not braces
 as one might become accustomed to seeing in CMake).

 *********************************************************************
")


################## CMAKE Version ###########################
# Make sure we're using CMAKE 3.1 or higher, ideally the latest
# From https://cliutils.gitlab.io/modern-cmake/chapters/basics.html
############################################################
cmake_minimum_required(VERSION 3.14)

if(${CMAKE_VERSION} VERSION_LESS 3.15)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
else()
    cmake_policy(VERSION 3.15)
endif()


################# CMake Project ############################
# The main options of project                              #
############################################################
set(MASTER_PROJECT_NAME lib-seeded)
project(${MASTER_PROJECT_NAME}
    VERSION 0.10
    DESCRIPTION "Libraries for working with seeded cryptography built on lib-sodium."
    LANGUAGES CXX
)
# Define Release by default.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
  message(STATUS "Build type not specified: Use Release by default.")
endif(NOT CMAKE_BUILD_TYPE)
get_filename_component(SEEDED_PROJECT_DIR "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)

message("${MASTER_PROJECT_NAME}: MAIN PROJECT CMAKE_SOURCE_DIR: ${CMAKE_SOURCE_DIR}")
message("${MASTER_PROJECT_NAME}: MAIN PROJECT CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message("${MASTER_PROJECT_NAME}: MAIN PROJECT CMAKE_BINARY_DIR: ${CMAKE_BINARY_DIR}")
message("${MASTER_PROJECT_NAME}: MAIN PROJECT CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")

####################################################
# External libraries to build
#
####################################################

####################################################
# Ensure libSodium is installed
include("extern/libsodium.cmake")

####################################################
# Libraries to build
####################################################
add_subdirectory("lib-seeded")

#############################################################
# Doxygen documentation
#############################################################

# first we can indicate the documentation build as an option and set it to ON by default
option(BUILD_DOC "Build documentation" ON)

# check if Doxygen is installed
find_package(Doxygen)
if (DOXYGEN_FOUND)
    # set input and output files
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/Doxyfile.out)

    # request to configure the file
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    message("Doxygen build started")

    # note the option ALL which allows to build the docs together with the application
    add_custom_target( doc_doxygen ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )

    message("Doxygen build block complete")

else (DOXYGEN_FOUND)
  message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)

#############################################################
# Testing
###########
#
# Must come after the libraries being tested
#
#############################################################

option(SEEDED_CREATE_AND_RUN_TESTS "Create and run tests" False)
message("SEEDED_CREATE_AND_RUN_TESTS=${SEEDED_CREATE_AND_RUN_TESTS}")
if ("${SEEDED_CREATE_AND_RUN_TESTS}" STREQUAL "True")
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()


######################### Flags ############################
# Defines Flags for Windows and Linux                      #
############################################################

if(NOT MSVC)
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
   if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
   endif()
endif(NOT MSVC)

# Preprocessor definitions
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(${MASTER_PROJECT_NAME} PRIVATE 
   -D_DEBUG 
   -D_CONSOLE
    )
    if(MSVC)
        target_compile_options(${MASTER_PROJECT_NAME} PRIVATE /W3 /Od /EHsc) # / Zi /MD
		message("*************************************")
    endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(${MASTER_PROJECT_NAME} PRIVATE 
   -DNDEBUG 
   -D_CONSOLE 
    )
    if(MSVC)
        target_compile_options(${MASTER_PROJECT_NAME} PRIVATE /W3 /GL /Oi /Gy /EHsc) # /Zi
    endif()
endif()

########### Link & Dependencies ############################
# Add project dependencies and Link to project             #
############################################################

if(MSVC)
#   target_link_libraries(${MASTER_PROJECT_NAME} PRIVATE Ws2_32.lib )
endif(MSVC)
