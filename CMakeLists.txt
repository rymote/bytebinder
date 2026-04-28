# bytebinder - A C++ Library for Low-Level Memory Manipulation
#
# Authors: Péter Marton, Jovan Ivanovic
# License: MIT
#
# This file is part of bytebinder, a powerful tool for reading, writing, hooking, and manipulating memory addresses.
#
# Repository: https://github.com/rymote/bytebinder

cmake_minimum_required(VERSION 3.28)

project(bytebinder
    VERSION 0.2.0
    LANGUAGES CXX
)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BYTEBINDER_BUILD_STATIC "Build the static archive target" ON)
option(BYTEBINDER_BUILD_SHARED "Build the shared library target" ON)
option(BYTEBINDER_BUILD_TESTS  "Build the Catch2 test runner"
       ${PROJECT_IS_TOP_LEVEL})
option(BYTEBINDER_ENABLE_SANITIZERS "Enable AddressSanitizer + UBSan in Debug builds" OFF)
option(BYTEBINDER_BUILD_USAGE_EXAMPLES "Compile docs/usage/*.cpp as smoke targets" OFF)

# Use the dynamic CRT on MSVC (/MD[d]) so EXE + libbytebinder.dll share one
# heap and STL allocator. With the static CRT (/MT[d]) each module has its own,
# which corrupts or hangs any std::string/vector/shared_ptr that crosses the
# DLL boundary (e.g. mem::scan, process::current, mem::disasm). PolyHook is
# pinned to the same runtime for the same reason.
set(POLYHOOK_BUILD_STATIC_RUNTIME OFF CACHE BOOL "")

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/deps/polyhook)

# Workaround: PolyHook 8cd6cb4 forgot #include <iterator> in x64Detour.cpp;
# inject it via the compiler so we don't have to patch the submodule.
if(NOT MSVC)
    target_compile_options(PolyHook_2 PRIVATE -include iterator)
endif()

set(BYTEBINDER_PUBLIC_HEADERS
    include/bb_api.h
    include/bb_code_scan.h
    include/bb_disasm.h
    include/bb_dump.h
    include/bb_heuristics.h
    include/bb_init_system.h
    include/bb_local_accessor.h
    include/bb_log_sink.h
    include/bb_macros.h
    include/bb_mem.h
    include/bb_memory_accessor.h
    include/bb_memory_exceptions.h
    include/bb_pattern.h
    include/bb_pch.h
    include/bb_process.h
    include/bb_remote_accessor.h
    include/bb_scoped_unlock.h
    include/bb_symbols.h
    include/bb_typed_scan.h
    include/bb_version.h
    include/bb_vmt.h
    include/bytebinder.h
)

set(BYTEBINDER_SOURCES
    src/bb_code_scan.cpp
    src/bb_disasm.cpp
    src/bb_dump.cpp
    src/bb_heuristics.cpp
    src/bb_local_accessor.cpp
    src/bb_log_sink.cpp
    src/bb_mem.cpp
    src/bb_memory_exceptions.cpp
    src/bb_pattern.cpp
    src/bb_remote_accessor.cpp
    src/bb_scoped_unlock.cpp
    src/bb_symbols.cpp
    src/bb_version.cpp
    src/bb_vmt.cpp
    src/process.cpp
)

add_library(bytebinder-objects OBJECT
    ${BYTEBINDER_SOURCES}
    ${BYTEBINDER_PUBLIC_HEADERS}
)

target_include_directories(bytebinder-objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/polyhook
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/polyhook/zydis/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/polyhook/zydis/dependencies/zycore/include
)

target_link_libraries(bytebinder-objects PUBLIC PolyHook_2)
if(WIN32)
    target_link_libraries(bytebinder-objects PUBLIC dbghelp)
endif()
target_precompile_headers(bytebinder-objects PUBLIC include/bb_pch.h)

target_compile_definitions(bytebinder-objects PRIVATE
    BYTEBINDER_VERSION_STRING="${PROJECT_VERSION}")

if(BYTEBINDER_ENABLE_SANITIZERS AND NOT MSVC)
    target_compile_options(bytebinder-objects PUBLIC
        $<$<CONFIG:Debug>:-fsanitize=address;-fsanitize=undefined;-fno-omit-frame-pointer>
    )
    target_link_options(bytebinder-objects PUBLIC
        $<$<CONFIG:Debug>:-fsanitize=address;-fsanitize=undefined>
    )
endif()

set(BYTEBINDER_BUILT_TARGETS "")

if(BYTEBINDER_BUILD_STATIC)
    add_library(bytebinder-static STATIC $<TARGET_OBJECTS:bytebinder-objects>)
    target_link_libraries(bytebinder-static PUBLIC bytebinder-objects)
    set_target_properties(bytebinder-static PROPERTIES
        OUTPUT_NAME bytebinder
        EXPORT_NAME static
    )
    list(APPEND BYTEBINDER_BUILT_TARGETS bytebinder-static)
endif()

if(BYTEBINDER_BUILD_SHARED)
    add_library(bytebinder-shared SHARED $<TARGET_OBJECTS:bytebinder-objects>)
    target_link_libraries(bytebinder-shared PUBLIC bytebinder-objects)
    target_compile_definitions(bytebinder-objects PRIVATE BYTEBINDER_BUILD_SHARED)
    target_compile_definitions(bytebinder-shared INTERFACE BYTEBINDER_USE_SHARED)
    set_target_properties(bytebinder-shared PROPERTIES
        OUTPUT_NAME bytebinder
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        EXPORT_NAME shared
    )
    list(APPEND BYTEBINDER_BUILT_TARGETS bytebinder-shared)
endif()

if(BYTEBINDER_BUILT_TARGETS)
    set_target_properties(${BYTEBINDER_BUILT_TARGETS} PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
endif()

install(TARGETS ${BYTEBINDER_BUILT_TARGETS} bytebinder-objects PolyHook_2
    EXPORT bytebinderTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES ${BYTEBINDER_PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bytebinder)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/bytebinderConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/bytebinderConfig.cmake
"include(\"\${CMAKE_CURRENT_LIST_DIR}/bytebinderTargets.cmake\")\n")

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/bytebinderConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/bytebinderConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bytebinder)

install(EXPORT bytebinderTargets
    NAMESPACE bytebinder::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bytebinder)

if(BYTEBINDER_BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.6.0
    )
    FetchContent_MakeAvailable(Catch2)

    add_executable(bytebinder-tests tests/tests.cpp)
    target_link_libraries(bytebinder-tests
        PRIVATE
            $<IF:$<TARGET_EXISTS:bytebinder-static>,bytebinder-static,bytebinder-shared>
            Catch2::Catch2WithMain)
    set_target_properties(bytebinder-tests PROPERTIES
        OUTPUT_NAME bytebinder_tests
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )

    include(CTest)
    include(Catch)
    catch_discover_tests(bytebinder-tests)
endif()

if(BYTEBINDER_BUILD_USAGE_EXAMPLES)
    add_subdirectory(docs/usage)
endif()
