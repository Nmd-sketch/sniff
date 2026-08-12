cmake_minimum_required(VERSION 3.20)
project(sniff VERSION 0.1.0 LANGUAGES CXX)

# --- Build options ---
option(BUILD_TESTS "Build unit tests" ON)

# --- C++ standard ---
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Compiler Warnings ---
if (MSVC)
    add_compile_options(/W4 /WX /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# --- Added subdirectories ---
add_subdirectory(src/domain)
add_subdirectory(src/application)
add_subdirectory(src/infrastructure)
add_subdirectory(src/interface)

# --- Main executable ---
add_executable(sniff src/main.cpp)
target_link_libraries(sniff PRIVATE
    interface_layer
    application_layer
    infrastructure_layer
    domain_layer
)

# --- Tests ---
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()



