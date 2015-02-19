cmake_minimum_required (VERSION 2.8)

project (usedef-checker)
#set(CMAKE_BUILD_TYPE Release)

# Set up relavant paths

# Paths to LLVM source and build trees
set(LLVM_HOME /home/bhargava/work/clang-analyzer/git-mirror-test)
set(LLVM_SRC_DIR ${LLVM_HOME}/llvm)
set(CLANG_SRC_DIR ${LLVM_SRC_DIR}/tools/clang)
set(LLVM_BUILD_DIR /home/bhargava/workspace/llvm)
set(CLANG_BUILD_DIR ${LLVM_BUILD_DIR}/tools/clang)

# Flags to compile checker code
set (CMAKE_CXX_FLAGS "-std=c++11 -fPIC -fno-common -Wcast-qual -fno-strict-aliasing -Wno-long-long -Wall -Wno-unused-parameter -Wwrite-strings -fno-rtti")

# Add paths to include and libs here
add_definitions(${LLVM_DEFINITIONS})
include_directories( "${LLVM_SRC_DIR}/include"
    "${CLANG_SRC_DIR}/include"
    "${CLANG_SRC_DIR}/lib/StaticAnalyzer/Checkers"
    "${LLVM_BUILD_DIR}/include"
    "${CLANG_BUILD_DIR}/include"
    "${CLANG_BUILD_DIR}/lib/StaticAnalyzer/Checkers")
link_directories(${LLVM_LIBRARY_DIRS})

# Make a shared library out of the checker. Can be loaded by scan-build -load-plugin
add_library( usedef-checker SHARED Myfirstchecker.cpp )

#### Not necessary

# Locate llvm
#find_package(LLVM)

# Necessary for out of source builds; Hooks plugin on to LLVM source tree
#set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} /home/bhargava/work/clang-analyzer/git-mirror-test/llvm/cmake/modules )

# Path to llvm-config binary is required for some reason
#set(LLVM_CONFIG /home/bhargava/work/clang-analyzer/git-mirror-test/llvm/bin/llvm-config)

#add_definitions (-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS)
#add_definitions (-DHAVE_CLANG_CONFIG_H )

#set (CMAKE_MODULE_LINKER_FLAGS "-Wl,-flat_namespace -Wl,-undefined -Wl,suppress")

#if (SYMBOL_FILE)
#  set_target_properties( ${name} PROPERTIES LINK_FlAGS
#    "-exported_symbols_list ${SYMBOL_FILE}")
#endif()

#### Not necessary
