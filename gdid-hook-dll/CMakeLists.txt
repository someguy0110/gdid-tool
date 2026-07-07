cmake_minimum_required(VERSION 3.20)
project(gdid-hook VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MinHook via FetchContent
include(FetchContent)
FetchContent_Declare(
    MinHook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG master
)
FetchContent_MakeAvailable(MinHook)

add_library(gdid-hook SHARED
    dllmain.cpp
    hook.cpp
)

target_link_libraries(gdid-hook PRIVATE MinHook)
target_compile_definitions(gdid-hook PRIVATE _CRT_SECURE_NO_WARNINGS)

# Output to build/ directory
set_target_properties(gdid-hook PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Install
install(TARGETS gdid-hook RUNTIME DESTINATION bin)