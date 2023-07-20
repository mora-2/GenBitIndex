# 设置最低 CMake 版本
cmake_minimum_required(VERSION 3.10)

# 设置 C++ 标准为 C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置项目名称和版本号
project(MyProject VERSION 1.0)

# 寻找 SEAL 库
find_package(SEAL 4.1.1 EXACT REQUIRED)

# 查找 Boost 库并设置相关变量
find_package(Boost REQUIRED COMPONENTS filesystem)

# 添加子文件夹
add_subdirectory("/home/yuance/Work/Encryption/PIR/code/HE/FHE/Clinet-Sever/Sever/src")
include_directories("/home/yuance/Work/Encryption/PIR/code/HE/FHE/Clinet-Sever/Sever/inc")

# 添加可执行文件
add_executable(MyExecutable main.cpp)

# 链接 SEAL 库
target_link_libraries(MyExecutable PRIVATE SEAL::seal)
target_link_libraries(MyExecutable PRIVATE mylib)
# 链接 Boost 文件系统库
target_link_libraries(MyExecutable PRIVATE Boost::filesystem)
