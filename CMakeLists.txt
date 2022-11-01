cmake_minimum_required(VERSION 2.8.0)
project(hook_test)

file(GLOB SRCS *.cpp)

add_executable(test ${SRCS})

target_link_libraries(test
    dl
)