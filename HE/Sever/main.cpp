#include <iostream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "seal/seal.h"
#include <chrono>
#include "inc/util.h"
#include <cstddef>
#include "inc/session.h"
#include <boost/filesystem.hpp>
#include "inc/ThreadPool.h"
#include <vector>

using namespace std;
using namespace seal;
using namespace chrono;

#define PORT 8081
// std::vector<int> ansPorts = {8001};
std::vector<int> ansPorts = {8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8011, 8012, 8013, 8014};
size_t BUFFER_SIZE = 60001;
size_t RECEIVE_CACHE = 60000;
char OK[] = "OK!";

string PathDB = "/home/yuance/Work/Encryption/PIR/code/HE/FHE/Sketch/ERR_2000/sketch/sketch_1e6_1/db/db_100.out";
string out_dir = "/home/yuance/Work/Encryption/PIR/code/HE/FHE/Clinet-Sever/Sever/output/sketch_1e6_1/gp2";
static const int Header_db = 0; // 除了头部固定8个字节标志头, .bf.bv文件尾部有可能多余0，注意！！！！

size_t PloyDegree = 8192;
const int numThreads = 70;
// size_t SketchLength = 25000000;
size_t SketchLength = 1000000;
size_t HashNum = 1;
size_t query_card = 2;
int main()
{
#pragma region
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddress, clientAddress;
    char *buffer = new char[BUFFER_SIZE];

    // 创建服务器套接字
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    // setsockopt(serverSocket, SOL_SOCKET, SO_RCVBUF, &BUFFER_SIZE, sizeof(BUFFER_SIZE));
    if (serverSocket == -1)
    {
        std::cerr << "无法创建套接字" << std::endl;
        return -1;
    }

    // 设置服务器地址
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(PORT);

    // 将套接字与服务器地址绑定
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        std::cerr << "绑定套接字失败" << std::endl;
        return -1;
    }

    // 监听客户端连接
    if (listen(serverSocket, 1) < 0)
    {
        std::cerr << "监听失败" << std::endl;
        return -1;
    }

    std::cout << "等待客户端连接..." << std::endl;

    // 接受客户端连接
    socklen_t clientAddressLength = sizeof(clientAddress);
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (clientSocket < 0)
    {
        std::cerr << "接受连接失败" << std::endl;
        return -1;
    }

    std::cout << "客户端已连接" << std::endl;
#pragma endregion

#pragma region
    // 检查目录是否存在
    if (!boost::filesystem::exists(out_dir))
    {
        // 创建目录
        if (boost::filesystem::create_directories(out_dir))
        {
            // std::cout << "out_dir目录创建成功" << std::endl;
        }
        else
        {
            // std::cout << "out_dir目录创建失败" << std::endl;
        }
    }
    else
    {
        // std::cout << "out_dir目录已经存在" << std::endl;
    }
#pragma endregion

    int phase = 0; // 进行状态
    EncryptionParameters loaded_params;
    SEALContext context(loaded_params); // CKKS 上下文
    double scale = pow(2.0, 18);        // scale

    uint32_t slot_count = 0;
    uint32_t chunk_num = 0;
    vector<vector<Ciphertext>> query_encrypted;      // 接收到的询问语句
    size_t query_size = 0;                           // 加密的询问语句流的字节大小
    std::stringstream received_query_stream;         // 字符流
    size_t query_receive_cnt = 0;                    // query接收次数
    std::string serializedData;                      // 装载answer向量
    size_t answer_send_cnt[ansPorts.size()] = {0};   // ans 需要发送的次数
    size_t answer_sended_cnt[ansPorts.size()] = {0}; // 当前发送的query次数（从0开始计数）
    size_t answer_send_cnt1, answer_sended_cnt1 = 0;

    vector<int> sever_socketIds(ansPorts.size(), 0);   // 多端口发送enc answer
    vector<int> client_socketIds(ansPorts.size(), -1); // TCP连接
    // socketInit(sever_socketIds, ansPorts, client_socketIds); // 初始化端口

    // 从客户端接收数据并发送响应
    while (true)
    {

        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead;
        bytesRead = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (bytesRead == -1)
        {
            // 处理接收错误的情况
            break;
        }
        else if (bytesRead == 0)
        {
            // 连接已关闭，接收完成
            break;
        }
        else
        {
            // 处理接收到的数据
            if (phase == 0) // receive CKKS Context
            {
                // 接收字节流
                std::stringstream paramsStream;
                // 接收数据流
                paramsStream.write(buffer, bytesRead);

                // 将接收到的字节流转换为EncryptionParameters对象
                loaded_params.load(paramsStream);
                context = SEALContext(loaded_params);

                CKKSEncoder encoder(context);      // encoder
                slot_count = encoder.slot_count(); // 最大编码向量长度
                chunk_num = ceil(SketchLength / double(slot_count));

                // std::cout << "接收到消息: " << std::endl;
                // print_parameters(context);

                std::string response = "";
                if (context.key_context_data()->parms().scheme() == seal::scheme_type::ckks)
                {
                    response += "scheme: ckks";
                    // cout << response << endl;
                }
                else
                {
                    response = "unknown scheme.";
                    // cout << response << endl;
                    return 1;
                }

                // 发送响应给客户端
                if (send(clientSocket, response.c_str(), response.length(), 0) < 0)
                {
                    std::cerr << "发送响应失败" << std::endl;
                    break;
                }
                phase++;
                cout << "1. received CKKS params" << endl;
            }
            else if (phase == 1) // receive query header
            {
                query_encrypted = vector<vector<Ciphertext>>(HashNum, vector<Ciphertext>(chunk_num)); // 初始化询问语句大小

                query_size = std::stoul(string(buffer, bytesRead));
                query_receive_cnt = query_size / RECEIVE_CACHE + 1;
                // cout << "query_size:" << query_size << endl;

                std::string response = "enc query header bytesRead: " + std::to_string(bytesRead);
                // 发送响应给客户端
                if (send(clientSocket, response.c_str(), response.length(), 0) < 0)
                {
                    std::cerr << "发送响应失败" << std::endl;
                    break;
                }
                phase++;
                cout << "2. received enc query header" << endl;
            }
            else if (phase == 2) // receive enc query
            {

                received_query_stream << string(buffer, bytesRead);
                query_receive_cnt--;
                // cout << "enc query bytesRead:" << bytesRead << endl;

                // 反序列化接收到的数据
                if (query_receive_cnt == 0) // enc query 接收完毕
                {
                    for (int i = 0; i < HashNum; i++)
                    {
                        for (int j = 0; j < chunk_num; j++)
                        {
                            query_encrypted[i][j].load(context, received_query_stream);
                        }
                    }
                    // cout << "enc query loaded!" << endl;
                    cout << "3. received enc query" << endl;
                    // 清空和重置 std::stringstream 对象
                    received_query_stream.str(""); // 清空内容
                    received_query_stream.clear(); // 重置状态
                                                   // 检查是否已清空
                    if (received_query_stream.str().empty())
                    {
                        std::cout << "receive stringstream is empty" << std::endl;
                    }
                    phase++;
                    std::string response = "enc query received!";
                    // 发送响应给客户端
                    if (send(clientSocket, response.c_str(), response.length(), 0) < 0)
                    {
                        std::cerr << "发送响应失败" << std::endl;
                        break;
                    }
                }
                else
                {
                    // std::string response = "收到消息: enc query bytesRead: " + std::to_string(bytesRead) + "\t 剩余接收次数：" + std::to_string(query_receive_cnt);
                    string response(OK);
                    // 发送响应给客户端
                    if (send(clientSocket, response.c_str(), response.length(), 0) < 0)
                    {
                        std::cerr << "发送响应失败" << std::endl;
                        break;
                    }
                }
            }
            else if (phase == 3) // Compute && send answer header
            {
                Evaluator evaluator(context);
                CKKSEncoder encoder(context); // encoder
                cout << "客户端发来消息：" << string(buffer, bytesRead) << endl;
                // Load DB
                //  get file size
                size_t file_bit_length = file_byte_length(PathDB) * 8;
                size_t sketch_num = file_bit_length / (SketchLength + Header_db);
                if (file_bit_length % (SketchLength + Header_db) != 0)
                {
                    std::cerr << "Error: db size error. Integreation Check Failed!\t file_bit_length: " << file_bit_length << "\t sketch num: "
                              << sketch_num << "\t remain bytes: " << file_bit_length % (SketchLength + Header_db) << endl;
                    return 1;
                }
                // put stream
                ThreadPool pool(numThreads);
                vector<std::stringstream> answer_stream(sketch_num); // 响应向量对应的字节流变量
                for (size_t i = 0; i < sketch_num; i++)              // 文件中Sketch的个数
                {
                    size_t st_load_index = i * (SketchLength + Header_db) + Header_db;

                    size_t hash_index = (st_load_index / (SketchLength + Header_db)) % HashNum;
                    size_t db_index = st_load_index / ((SketchLength + Header_db) * HashNum);
                    size_t query_i = 0;
                    pool.enqueue(std::bind(sever_subtask, ref(PathDB), ref(st_load_index), ref(SketchLength), ref(chunk_num), ref(slot_count),
                                           ref(encoder), ref(scale),
                                           ref(evaluator), ref(query_encrypted[hash_index]), ref(answer_stream[i]),
                                           hash_index, ref(db_index),
                                           query_i, ref(query_card), ref(out_dir)));
                }
                // 等待所有任务完成
                pool.wait();

                for (size_t i = 0; i < sketch_num; i++)
                {
                    serializedData += answer_stream[i].str();
                    // serializedData += answer_stream[i].str().length();
                    // cout << " answer_stream[i].str().length():" << answer_stream[i].str().length() << endl;
                }

                answer_send_cnt1 = serializedData.length() / RECEIVE_CACHE;
                for (int i = 0; i < ansPorts.size(); i++)
                {
                    answer_send_cnt[i] = ((serializedData.length() / RECEIVE_CACHE + 1) / ansPorts.size()) - 1;
                    if (i == ansPorts.size() - 1)
                    {
                        answer_send_cnt[i] += (serializedData.length() / RECEIVE_CACHE + 1) % ansPorts.size();
                    }
                }

                string response = std::to_string(serializedData.length()) + ',' + std::to_string(sketch_num);

                // 发送序列化后的数据给客户端
                if (send(clientSocket, response.c_str(), response.length(), 0) < 0)
                {
                    std::cerr << "发送encrypted answer header 失败." << std::endl;
                    break;
                }
                // cout << "answer header发送完毕" << endl;
                cout << "4. send enc answer header" << endl;
                phase++; 
            }
            else if (phase == 4) // send answer
            {
                // cout << "客户端发来消息：" << string(buffer, bytesRead) << endl;

                // 创建线程发送数据到不同的端口
                vector<thread> threads(ansPorts.size());
                for (int i = 0; i < ansPorts.size(); i++)
                {
                    threads[i] = thread(socketTask, ref(sever_socketIds[i]), ref(ansPorts[i]), ref(client_socketIds[i]),
                                        (answer_send_cnt[0] + 1) * i * RECEIVE_CACHE, ((ansPorts.size() - 1) == i ? 1 : 0), answer_send_cnt[i], ref(RECEIVE_CACHE), ref(BUFFER_SIZE),
                                        ref(serializedData));
                }
                // 等待线程结束
                for (int i = 0; i < ansPorts.size(); i++)
                {
                    threads[i].join();
                    close(sever_socketIds[i]);
                    close(client_socketIds[i]);

                    // if (((ansPorts.size() - 1) == i ? 1 : 0))
                    // {
                    //     cout << "last socket:" << i << endl;
                    // }
                    // cout << "socket id:" << i << "  socket:" << client_socketIds[i] << endl;
                }


                // for (int i = 0; i < ansPorts.size(); i++)
                // {
                //     cout << "answer_send_cnt[" << i << "]:" << answer_send_cnt[i] << endl;
                // }

                cout << "5. send enc answer" << endl;
                phase++;

                // if (answer_sended_cnt1 < answer_send_cnt1) // query发送
                // {
                //     // 发送序列化后的数据给服务器
                //     if (send(clientSocket, serializedData.substr(answer_sended_cnt1 * RECEIVE_CACHE, RECEIVE_CACHE).c_str(), RECEIVE_CACHE, 0) < 0)
                //     {
                //         std::cerr << "发送encrypted answer数据失败" << std::endl;
                //         break;
                //     }
                //     answer_sended_cnt1++;
                // }
                // else if (answer_sended_cnt1 == answer_send_cnt1) // query发送完毕
                // {
                //     // 发送序列化后的数据给服务器
                //     if (send(clientSocket, serializedData.substr(answer_sended_cnt1 * RECEIVE_CACHE).c_str(), serializedData.length() % RECEIVE_CACHE, 0) < 0)
                //     {
                //         std::cerr << "发送encrypted answer失败" << std::endl;
                //         break;
                //     }
                //     // cout << "enc answer发送完毕" << endl;
                //     cout << "5. send enc answer" << endl;
                //     phase++;
                // }
            }
            else
            {
                std::cout << "接收到消息: " << buffer << std::endl;
                std::string response = "收到消息: ";
                response += buffer;

                // 发送响应给客户端
                if (send(clientSocket, response.c_str(), response.length(), 0) < 0)
                {
                    std::cerr << "发送响应失败" << std::endl;
                    break;
                }
                phase++;
            }
        }
    }

    delete[] buffer;
    // 关闭套接字
    close(clientSocket);
    close(serverSocket);

    return 0;
}
