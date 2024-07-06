# bytebinder - A C++ Library for Low-Level Memory Manipulation
#
# Authors: Péter Marton, Jovan Ivanovic
# License: MIT
#
# This file is part of bytebinder, a powerful tool for reading, writing, hooking, and manipulating memory addresses.
#
# Repository: https://github.com/rymote/bytebinder
#
# For issues, suggestions, or contributions, please visit the repository or contact the authors.
#
# This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties
# of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders
# be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out
# of, or in connection with the software or the use or other dealings in the software.

cmake_minimum_required(VERSION 3.28)

set(PROJECT_NAME bytebinder)
project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(POLYHOOK_BUILD_STATIC_RUNTIME ON CACHE BOOL "")

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.h")
file(GLOB_RECURSE TESTS "tests/*.cpp")

include_directories(include)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/deps/polyhook)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/polyhook)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/polyhook/zydis/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/deps/polyhook/zydis/dependencies/zycore/include)

add_library(${PROJECT_NAME}-static STATIC ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME}-static PolyHook_2)

add_library(${PROJECT_NAME}-shared SHARED ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME}-shared PolyHook_2)

set_target_properties(${PROJECT_NAME}-static PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME}-shared PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

set_target_properties(${PROJECT_NAME}-shared PROPERTIES
    OUTPUT_NAME ${PROJECT_NAME}
    PUBLIC_HEADER "${HEADERS}"
)

set_target_properties(${PROJECT_NAME}-static PROPERTIES
    OUTPUT_NAME ${PROJECT_NAME}
    PUBLIC_HEADER "${HEADERS}"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

target_precompile_headers(${PROJECT_NAME}-static PUBLIC include/pch.h)
target_precompile_headers(${PROJECT_NAME}-shared PUBLIC include/pch.h)

install(TARGETS ${PROJECT_NAME}-static ${PROJECT_NAME}-shared
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION lib
    PUBLIC_HEADER DESTINATION include/${PROJECT_NAME}
)

include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.6.0
)
FetchContent_MakeAvailable(Catch2)

add_executable(${PROJECT_NAME}-tests ${TESTS} ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME}-tests PRIVATE Catch2::Catch2 Catch2::Catch2WithMain PolyHook_2)
set_target_properties(${PROJECT_NAME}-tests PROPERTIES OUTPUT_NAME ${PROJECT_NAME}_tests)

include(CTest)
include(Catch)

catch_discover_tests(${PROJECT_NAME}-tests)