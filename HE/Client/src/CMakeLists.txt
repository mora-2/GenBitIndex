# 获取所有 .cpp 文件
file(GLOB SOURCES "*.cpp")

# 获取所有 .h 文件
file(GLOB HEADERS "/home/yuance/Work/Encryption/PIR/code/HE/FHE/Clinet-Sever/Client/inc/*.h")

# 将源文件和头文件添加到一个库中
add_library(mylib STATIC ${SOURCES} ${HEADERS})

# 链接 SEAL 库到子目标中
target_link_libraries(mylib SEAL::seal)

# 设置库文件的输出目录
set_target_properties(mylib PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
)

# 设置头文件的包含路径
target_include_directories(mylib PUBLIC /home/yuance/Work/Encryption/PIR/code/HE/FHE/Clinet-Sever/Client/inc)