cmake_minimum_required(VERSION 3.10)
project(padd_01)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加头文件搜索路径
include_directories(
    include
    $ENV{HOME}/.local/include/pbc
)

# 定义可执行文件及其源文件
add_executable(padd_01
    src/main.cpp
    src/padd_01.cpp
    src/utils.cpp
)

# 设置可执行文件的运行时路径
set_target_properties(padd_01 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# 添加库搜索路径
link_directories($ENV{HOME}/.local/lib)

# 链接所需的库
target_link_libraries(padd_01
    pbc
    gmp
    crypto
    stdc++fs
)

# 设置运行时路径
set_target_properties(padd_01 PROPERTIES
    INSTALL_RPATH "$ENV{HOME}/.local/lib"
)

# cmake_minimum_required(VERSION 3.10)
# project(padd_01)

# # 设置C++标准
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED True)

# # 添加头文件搜索路径
# include_directories(
#     include
#     $ENV{HOME}/.local/include/pbc
# )

# # 定义主可执行文件及其源文件
# add_executable(padd_01
#     src/main.cpp
#     src/padd_01.cpp
#     src/utils.cpp
# )

# # 设置主可执行文件的运行时路径
# set_target_properties(padd_01 PROPERTIES
#     RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
# )

# # 添加库搜索路径
# link_directories($ENV{HOME}/.local/lib)

# # 链接主可执行文件所需的库
# target_link_libraries(padd_01
#     pbc
#     gmp
#     crypto
#     stdc++fs
# )

# # 设置主可执行文件的运行时路径
# set_target_properties(padd_01 PROPERTIES
#     INSTALL_RPATH "$ENV{HOME}/.local/lib"
# )

# # 启用测试
# enable_testing()

# # 检查测试目录是否存在
# if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test/test.cpp)
#     # 添加Google Test子目录 - 使用正确的配置方式
#     add_subdirectory(lib/googletest)
    
#     # 确保googletest目标已创建
#     if(TARGET gtest AND TARGET gtest_main)
#         # 定义测试可执行文件
#         add_executable(padd_01_test
#             test/test.cpp
#             src/padd_01.cpp
#             src/utils.cpp
#         )

#         # 设置测试可执行文件的输出目录
#         set_target_properties(padd_01_test PROPERTIES
#             RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
#         )

#         # 链接测试可执行文件所需的库
#         target_link_libraries(padd_01_test
#             pbc
#             gmp
#             crypto
#             stdc++fs
#             gtest
#             gtest_main
#         )

#         # 将测试添加到CTest
#         add_test(NAME padd_01_test COMMAND ${CMAKE_BINARY_DIR}/bin/padd_01_test)
#     else()
#         message(WARNING "Google Test targets not found - skipping test configuration")
#     endif()
# else()
#     message(WARNING "Test file test/test.cpp not found - skipping test configuration")
# endif()
