cmake_minimum_required(VERSION 3.10)
project(padd)  # 修改项目名

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加头文件搜索路径
include_directories(
    include
    $ENV{HOME}/.local/include/pbc
)

# 创建动态库，直接命名为padd
add_library(padd SHARED  # 直接使用padd作为目标名
    src/padd_01.cpp
    src/utils.cpp
    src/vrf.cpp
)

# 设置库的输出目录
set_target_properties(padd PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    VERSION 1.0.0
    SOVERSION 1
)

# 添加库搜索路径
link_directories($ENV{HOME}/.local/lib)

# 链接所需的库
target_link_libraries(padd
    pbc
    gmp
    crypto
    stdc++fs
)

# 可选：如果需要可执行文件
add_executable(padd_test src/main.cpp)
target_link_libraries(padd_test padd)
set_target_properties(padd_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# 设置运行时路径
set_target_properties(padd PROPERTIES
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

# # 定义可执行文件及其源文件
# add_executable(padd_01
#     src/main.cpp
#     src/padd_01.cpp
#     src/utils.cpp
#     src/vrf.cpp
# )

# # 设置可执行文件的运行时路径
# set_target_properties(padd_01 PROPERTIES
#     RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
# )

# # 添加库搜索路径
# link_directories($ENV{HOME}/.local/lib)

# # 链接所需的库
# target_link_libraries(padd_01
#     pbc
#     gmp
#     crypto
#     stdc++fs
# )

# # 设置运行时路径
# set_target_properties(padd_01 PROPERTIES
#     INSTALL_RPATH "$ENV{HOME}/.local/lib"
# )