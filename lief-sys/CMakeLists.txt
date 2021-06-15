cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)

include(ExternalProject)

project(lief-sys LANGUAGES CXX)

set(LIEF_PREFIX       "${CMAKE_CURRENT_BINARY_DIR}/LIEF")
set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")

set(LIB_LIEF "${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}")

set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

set(LIEF_VERSION 0.11.0)

set(LIEF_CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DLIEF_PE=ON
        -DLIEF_LOGGING=ON
        -DLIEF_ELF=ON
        -DLIEF_MACHO=OFF
        -DLIEF_PYTHON_API=OFF
        -DLIEF_ENABLE_JSON=OFF
        -DLIEF_EXAMPLES=OFF
        -DLIEF_DOC=OFF
        -DLIEF_COVERAGE=OFF
        -DLIEF_EXTRA_WARNINGS=OFF
        -DLIEF_ASAN=OFF
        -DLIEF_LSAN=OFF
        -DLIEF_TSAN=OFF
        -DLIEF_FUZZING=OFF
        -DLIEF_PROFILING=OFF
        -DLIEF_FROZEN_ENABLED=OFF
        -DLIEF_INSTALL_COMPILED_EXAMPLES=OFF
        -DLIEF_USE_CRT_DEBUG=MTd
        -DLIEF_USE_CRT_RELEASE=MT
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DBUILD_SHARED_LIBS=OFF
        -DCCACHE=OFF
        )

if(MSVC)
    if(${CMAKE_BUILD_TYPE} MATCHES "Release")
        list(APPEND ${LIEF_CMAKE_ARGS} -DLIEF_USE_CRT_RELEASE=/MT)
    else()
        list(APPEND ${LIEF_CMAKE_ARGS} -DLIEF_USE_CRT_DEBUG=/MTd)
    endif()
endif()

ExternalProject_Add(LIEF
        PREFIX           "${LIEF_PREFIX}"
        GIT_REPOSITORY   ${LIEF_GIT_URL}
        GIT_TAG          ${LIEF_VERSION}
        INSTALL_DIR      ${LIEF_INSTALL_DIR}
        CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
        BUILD_BYPRODUCTS ${LIEF_LIBRARIES}
        UPDATE_COMMAND   ""
        )

add_library(lief-sys src/liblief.cpp)

if(MSVC)
    target_compile_options(lief-sys PUBLIC /FIiso646.h)
    set_property(TARGET lief-sys PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_include_directories(lief-sys PUBLIC ${LIEF_INCLUDE_DIRS})

target_link_libraries(lief-sys PUBLIC ${LIB_LIEF})

add_dependencies(lief-sys LIEF)
