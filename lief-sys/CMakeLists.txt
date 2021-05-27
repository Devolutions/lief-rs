cmake_minimum_required(VERSION 3.0)

include(ExternalProject)

project(LIEF_SYS LANGUAGES CXX)

set(LIEF_PREFIX       "${CMAKE_CURRENT_BINARY_DIR}/LIEF")
set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIB_LIEF
        "${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}")

set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

set(LIEF_VERSION 0.11.0)

set(LIEF_CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DLIEF_PE=on
        -DLIEF_LOGGING=on
        -DLIEF_ELF=on
        -DLIEF_MACHO=off
        -DLIEF_PYTHON_API=off
        -DLIEF_ENABLE_JSON=off
        -DLIEF_EXAMPLES=off
        -DLIEF_DOC=off
        -DLIEF_COVERAGE=off
        -DLIEF_EXTRA_WARNINGS=off
        -DLIEF_ASAN=off
        -DLIEF_LSAN=off
        -DLIEF_TSAN=off
        -DLIEF_FUZZING=off
        -DLIEF_PROFILING=off
        -DLIEF_FROZEN_ENABLED=off
        -DLIEF_INSTALL_COMPILED_EXAMPLES=off
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCCACHE=off
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

add_library(LIEF_SYS SHARED src/liblief.cpp)

if(MSVC)
    target_compile_options(LIEF_SYS PUBLIC /FIiso646.h)
    if(${CMAKE_BUILD_TYPE} MATCHES "Release")
        set_property(TARGET LIEF_SYS PROPERTY MSVC_RUNTIME_LIBRARY "/MT")
    else()
        set_property(TARGET LIEF_SYS PROPERTY MSVC_RUNTIME_LIBRARY "/MTd")
    endif()
endif()


target_include_directories(LIEF_SYS PUBLIC ${LIEF_INCLUDE_DIRS})

target_link_libraries(LIEF_SYS PUBLIC ${LIB_LIEF})

add_dependencies(LIEF_SYS LIEF)

