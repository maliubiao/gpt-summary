cmake_minimum_required(VERSION 3.10)
project(test_project)
# Generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use clang as the compiler
set(CMAKE_CXX_COMPILER clang++)

# Add the executable
add_executable(test.exe test.cpp)


