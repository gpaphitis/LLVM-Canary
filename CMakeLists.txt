cmake_minimum_required(VERSION 3.13)
project(Canary LANGUAGES C CXX)

# Specify where to find LLVM
set(LLVM_DIR "/home/george/llvm-install/lib/cmake/llvm")
find_package(LLVM REQUIRED CONFIG)

# Set LLVM C++ flags and include paths
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# Add LLVM CMake modules to module path
list(APPEND CMAKE_MODULE_PATH "${LLVM_DIR}")
include(HandleLLVMOptions)
include(AddLLVM)

# Optional: Set C++ standard (LLVM usually expects C++14 or newer)
set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard to conform to")
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

# Add your custom pass as a plugin
add_llvm_pass_plugin(Canary
  Canary.cpp
)