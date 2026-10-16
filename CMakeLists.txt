cmake_minimum_required(VERSION 3.16)
project(NanoRay LANGUAGES CXX RC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-D_WIN32_WINNT=0x0A00)

add_executable(NanoRay WIN32
    src/main.cpp
    src/config.cpp
    src/tunnel.cpp
    src/ui_flyout.cpp
    resources/resource.rc
)
target_include_directories(NanoRay PRIVATE src)
target_link_libraries(NanoRay PRIVATE ws2_32 iphlpapi gdiplus dwmapi shell32 psapi ole32 gdi32 user32 winhttp secur32 crypt32 bcrypt)
if(MSVC)
    target_compile_options(NanoRay PRIVATE /O2 /W3 /EHsc)
    set_target_properties(NanoRay PROPERTIES LINK_FLAGS "/MANIFEST:NO")
else()
    target_compile_options(NanoRay PRIVATE -O3 -Wall)
    target_link_options(NanoRay PRIVATE -s -mwindows)
endif()