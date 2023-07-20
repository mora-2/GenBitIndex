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

using namespace std;
using namespace seal;
using namespace chrono;

// #define DEBUG
#ifdef DEBUG
#define SERVER_IP "127.0.0.1"
string query_dir = "/home/yuance/Work/Encryption/PIR/code/HE/FHE/Sketch/ERR_2000/query_index/gp2/sketch_1e6_1_gp2.txt";
string out_dir = "/home/yuance/Work/Encryption/PIR/code/HE/FHE/Clinet-Sever/Client/output/sketch_1e6_1/gp2";
size_t SketchLength = 1000000;
size_t BUFFER_SIZE = 60001;
size_t RECEIVE_CACHE = 60000;
#else
#define SERVER_IP "219.245.186.51"
string query_dir = "/home/yuance/Work/Encryption/PIR/code/HE/FHE/Sketch/ERR_2000/query_index/gp2/sketch_2.5e7_1_gp2.txt";
string out_dir = "/home/yuance/Work/Encryption/PIR/code/HE/FHE/Clinet-Sever/Client/output/sketch_2.5e7_1/gp2";
size_t SketchLength = 25000000;
size_t BUFFER_SIZE = 1001;
size_t RECEIVE_CACHE = 1000;
#endif
#define PORT 8081
// std::vector<int> ansPorts = {8001};
std::vector<int> ansPorts = {8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8011, 8012, 8013, 8014};

char OK[] = "OK!";

static const int Header_db = 0; // 除了头部固定8个字节标志头, .bf.bv文件尾部有可能多余0，注意！！！！
size_t PloyDegree = 8192;
const int numThreads = 70;
size_t HashNum = 1;
size_t query_card = 2;

int main()
{
    auto p_start = high_resolution_clock::now(); // 获取开始时间点
#pragma region
    int clientSocket;
    struct sockaddr_in serverAddress;
    char buffer[BUFFER_SIZE];

    // 创建客户端套接字
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    // setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, &BUFFER_SIZE, sizeof(BUFFER_SIZE));
    if (clientSocket == -1)
    {
        std::cerr << "无法创建套接字" << std::endl;
        return -1;
    }

    // 设置服务器地址
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);

    // 将IP地址从文本转换为二进制形式
    if (inet_pton(AF_INET, SERVER_IP, &(serverAddress.sin_addr)) <= 0)
    {
        std::cerr << "无效的服务器IP地址" << std::endl;
        return -1;
    }

    // 连接到服务器
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        std::cerr << "连接到服务器失败" << std::endl;
        return -1;
    }

    std::cout << "已连接到服务器" << std::endl;
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

#pragma region
    // CKKS params
    auto start = high_resolution_clock::now(); // 获取开始时间点

    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = PloyDegree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {20, 18, 20}));

    double scale = pow(2.0, 18);
    SEALContext context(parms);
    // print_parameters(context);
    // cout << "-----------------------------------" << endl;
    // cout << "numThreads:" << numThreads << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    uint32_t slot_count = encoder.slot_count(); // 最大编码向量长度
    uint32_t chunk_num = ceil(SketchLength / double(slot_count));

    // cout << "max vector dim size:" << slot_count << endl;
    // cout << "chunk_num:" << chunk_num << endl;
    // cout << "-----------------------------------" << endl;
    auto end = high_resolution_clock::now();                  // 获取结束时间点
    auto duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    cout << "1. params set运行时间: " << duration.count() / 1000.0 << " 秒" << endl;
#pragma endregion

    // get query path
    vector<string> query_path = get_query_path(query_dir);

    int phase = 0;               // 进行状态
    size_t query_send_cnt = 0;   // 需要发送query的次数（从0开始计数）
    size_t query_sended_cnt = 0; // 当前发送query的次数（从0开始计数）
    std::string serializedData;
    size_t answer_size;
    vector<size_t> answer_receive_cnt(ansPorts.size()); // 需要接收answer的次数（从0开始计数）
    // std::stringstream received_answer_stream; // 字符流
    vector<std::stringstream> received_answer_stream(ansPorts.size()); // 字符流

    vector<int> client_socketIds(ansPorts.size(), 0); // 多端口接收enc answer
    // socketInit(client_socketIds, ansPorts, SERVER_IP);

    size_t sketch_num = 0;
    vector<Ciphertext> Encrypted_Result;
    time_point<std::chrono::high_resolution_clock> end0, end1, end2, end3, end4, end5, end6;
    // 发送数据给服务器并接收响应
    while (true)
    {
        if (phase == 0) // 发送CKKS加密参数
        {
            // 保存参数到字节流
            std::stringstream params_stream;
            parms.save(params_stream);
            // 获取参数字节流
            std::string params_data = params_stream.str();

            // 发送context给服务器
            if (send(clientSocket, params_data.c_str(), params_data.size(), 0) < 0)
            {
                std::cerr << "发送CKKS params消息失败" << std::endl;
                break;
            }
            phase++;
            end0 = high_resolution_clock::now();                // 获取结束时间点
            duration = duration_cast<milliseconds>(end0 - end); // 计算运行时间
            cout << "2. send CKKS params:" << duration.count() / 1000.0 << " 秒" << endl;
        }
        else if (phase == 1) // send enc query header & make enc query
        {
            // vector<vector<Ciphertext>> query_encrypted(HashNum, vector<Ciphertext>(chunk_num));
            // 保存数据到字节流
            std::stringstream query_data_stream;
            client_query_read(encoder, chunk_num, slot_count, scale,
                              query_path[0], size_t(0), query_card, out_dir, SketchLength, HashNum,
                              encryptor, secret_key, query_data_stream);

            // 序列化数据结构
            serializedData = query_data_stream.str();
            query_send_cnt = serializedData.length() / RECEIVE_CACHE;
            // cout << "send enc query bytesLength:" << serializedData.length() << endl;
            // 发送序列化后的数据给服务器
            if (send(clientSocket, std::to_string(serializedData.length()).c_str(), std::to_string(serializedData.length()).length(), 0) < 0)
            {
                std::cerr << "发送encrypted query length 失败." << std::endl;
                break;
            }
            phase++;
            end1 = high_resolution_clock::now();                 // 获取结束时间点
            duration = duration_cast<milliseconds>(end1 - end0); // 计算运行时间
            cout << "3. enc query && send enc query header:" << duration.count() / 1000.0 << " 秒" << endl;
        }
        else if (phase == 2) // 发送query
        {
            if (query_sended_cnt < query_send_cnt) // query发送
            {
                // cout << "send byte enc query:" << serializedData.substr(query_sended_cnt * RECEIVE_CACHE, RECEIVE_CACHE).length() << endl;
                // 发送序列化后的数据给服务器
                if (send(clientSocket, serializedData.substr(query_sended_cnt * RECEIVE_CACHE, RECEIVE_CACHE).c_str(), RECEIVE_CACHE, 0) < 0)
                {
                    std::cerr << "发送encrypted query数据失败" << std::endl;
                    break;
                }
                query_sended_cnt++;
            }
            else if (query_sended_cnt == query_send_cnt) // query发送完毕
            {
                // 发送序列化后的数据给服务器
                if (send(clientSocket, serializedData.substr(query_sended_cnt * RECEIVE_CACHE).c_str(), serializedData.length() % RECEIVE_CACHE, 0) < 0)
                {
                    std::cerr << "发送encrypted query失败" << std::endl;
                    break;
                }
                phase++;
                end2 = high_resolution_clock::now();                 // 获取结束时间点
                duration = duration_cast<milliseconds>(end2 - end1); // 计算运行时间
                cout << "4. send enc query:" << duration.count() / 1000.0 << " 秒" << endl;
            }
        }
        else if (phase == 3) // 接收enc answer header
        {
            string response = "等待接收answer header";
            // 发送相应给服务器
            if (send(clientSocket, response.c_str(), response.length(), 0) < 0)
            {
                std::cerr << "发送encrypted query数据失败" << std::endl;
                break;
            }

            // 接收服务器响应
            ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesRead < 0)
            {
                std::cerr << "接收响应失败" << std::endl;
                break;
            }

            string data(buffer, bytesRead);
            size_t comma_pos = data.find(',');
            if (comma_pos != std::string::npos)
            {
                answer_size = std::stoul(data.substr(0, comma_pos));
                sketch_num = std::stoul(data.substr(comma_pos + 1));
            }

            for (int i = 0; i < ansPorts.size(); i++)
            {
                answer_receive_cnt[i] = ((answer_size / RECEIVE_CACHE + 1) / ansPorts.size());
                if (i == ansPorts.size() - 1)
                {
                    // cout << "before answer_receive_cnt:" << answer_receive_cnt[i] << endl;
                    answer_receive_cnt[i] += (answer_size / RECEIVE_CACHE + 1) % ansPorts.size();
                    // cout << "after answer_receive_cnt:" << answer_receive_cnt[i] << endl;
                }
            }

            Encrypted_Result = vector<Ciphertext>(sketch_num);
            phase++;
            end3 = high_resolution_clock::now();                 // 获取结束时间点
            duration = duration_cast<milliseconds>(end3 - end2); // 计算运行时间
            cout << "5. calculate enc answer && receive enc answer header:" << duration.count() / 1000.0 << " 秒" << endl;
            cout << "接收到header, 解算结果为:answer_size:" << answer_size << "\tsketch_num:" << sketch_num << endl;
            continue;
        }
        else if (phase == 4) // 接收enc answer && 解算 answer
        {
            string response = string("等待接收enc answer");
            // 发送响应
            if (send(clientSocket, response.c_str(), response.length(), 0) < 0)
            {
                std::cerr << "发送encrypted query数据失败" << std::endl;
                break;
            }

            // std::cout << "Start" << std::endl;
            // 休眠 3 秒, 等待服务器初始化完毕, 客户端再进行连接操作, 否则会导致连接失败
            std::this_thread::sleep_for(std::chrono::seconds(3));
            // std::cout << "End" << std::endl;
            // for (int i = 0; i < ansPorts.size(); i++)
            // {
            //     cout << "answer_receive_cnt[" << i << "]:" << answer_receive_cnt[i] << endl;
            // }

            // 创建线程发送数据到不同的端口
            vector<thread> threads(ansPorts.size());
            for (int i = 0; i < ansPorts.size(); i++)
            {
                threads[i] = thread(socketTask, i, ref(client_socketIds[i]), ref(ansPorts[i]), SERVER_IP,
                                    ref(BUFFER_SIZE), ref(answer_receive_cnt[i]), ref(received_answer_stream[i]));
            }

            // 等待线程结束
            for (int i = 0; i < ansPorts.size(); i++)
            {
                threads[i].join();
                close(client_socketIds[i]);
            }
            stringstream ans_stream;
            for (int i = 0; i < ansPorts.size(); i++)
            {
                ans_stream << received_answer_stream[i].str();
                // cout << "received_answer_stream[" << i << "] size:" << received_answer_stream[i].str().size() << endl;
                received_answer_stream[i].str(""); // 清空内容
                received_answer_stream[i].clear(); // 重置状态
                if (received_answer_stream[i].str().empty())
                {
                    // std::cout << "receive stringstream[" << i << "] is empty" << std::endl;
                }
                // cout << "answer_receive_cnt[" << i << "]:" << answer_receive_cnt[i] << endl;
            }
            end4 = high_resolution_clock::now();                 // 获取结束时间点
            duration = duration_cast<milliseconds>(end4 - end3); // 计算运行时间
            cout << "6. answer stream received:" << duration.count() / 1000.0 << " 秒" << endl;

            // cout << "answer_size:" << answer_size << "  received size:" << ans_stream.str().size() << endl;
            // std::this_thread::sleep_for(std::chrono::seconds(3));

            for (int i = 0; i < sketch_num; i++)
            {
                // cout << "i:" << i << endl;
                Encrypted_Result[i].load(context, ans_stream);
            }

            // 清空和重置 std::ans_stream 对象
            ans_stream.str(""); // 清空内容
            ans_stream.clear(); // 重置状态
                                // 检查是否已清空
            if (ans_stream.str().empty())
            {
                std::cout << "receive ans_stream is empty" << std::endl;
            }
            end5 = high_resolution_clock::now();                 // 获取结束时间点
            duration = duration_cast<milliseconds>(end5 - end4); // 计算运行时间
            cout << "7. answer load:" << duration.count() / 1000.0 << " 秒" << endl;

            // 解算 answer
            ThreadPool pool(numThreads);
            for (size_t i = 0; i < sketch_num; i++) // 文件中Sketch的个数
            {
                size_t st_load_index = i * (SketchLength + Header_db) + Header_db;
                size_t hash_index = (st_load_index / (SketchLength + Header_db)) % HashNum;
                size_t db_index = st_load_index / ((SketchLength + Header_db) * HashNum);
                size_t query_i = 0;
                pool.enqueue(std::bind(client_subanswer,
                                       ref(decryptor), ref(chunk_num), ref(Encrypted_Result[i]),
                                       ref(encoder), ref(slot_count), ref(hash_index), ref(db_index),
                                       ref(query_i), ref(query_card), ref(out_dir), ref(SketchLength)));
            }
            // 等待所有任务完成
            pool.wait();
            phase++;

            response = "answer decoded!";
            // cout << response << endl;
            end6 = high_resolution_clock::now();                 // 获取结束时间点
            duration = duration_cast<milliseconds>(end6 - end5); // 计算运行时间
            cout << "8. decode answer:" << duration.count() / 1000.0 << " 秒" << endl;
            auto p_end = high_resolution_clock::now();                      // 获取结束时间点
            auto p_duration = duration_cast<milliseconds>(p_end - p_start); // 计算运行时间
            cout << "******************************************************" << endl;
            cout << "\tDB record number:" << sketch_num / HashNum << endl;
            cout << "\tHASH size:" << SketchLength << endl;
            cout << "\tHASH number:" << HashNum << endl;
            cout << "\tTOTAL runtime:" << p_duration.count() / 1000.0 << "s" << endl;
            cout << "******************************************************" << endl;
            continue;

            // // 接收服务器响应
            // ssize_t bytesRead;
            // bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
            // if (bytesRead == -1)
            // {
            //     // 处理接收错误的情况
            //     break;
            // }
            // else if (bytesRead == 0)
            // {
            //     // 连接已关闭，接收完成
            //     break;
            // }
            // else
            // {

            //     // cout << "answer enc bytesRead:" << bytesRead << endl;
            //     // cout << "answer_receive_cnt:" << answer_receive_cnt << endl;
            //     received_answer_stream << string(buffer, bytesRead);
            //     answer_receive_cnt--;
            //     // 反序列化接收到的数据
            //     if (answer_receive_cnt == 0) // enc query 接收完毕
            //     {
            //         for (int i = 0; i < sketch_num; i++)
            //         {
            //             for (int j = 0; j < chunk_num; j++)
            //             {
            //                 Encrypted_Result[i][j].load(context, received_answer_stream);
            //             }
            //         }
            //         // cout << "enc answer loaded!" << endl;
            //         end4 = high_resolution_clock::now();                 // 获取结束时间点
            //         duration = duration_cast<milliseconds>(end4 - end3); // 计算运行时间
            //         cout << "6. receive && load enc answer:" << duration.count() / 1000.0 << " 秒" << endl;
            //         // 清空和重置 std::stringstream 对象
            //         received_answer_stream.str(""); // 清空内容
            //         received_answer_stream.clear(); // 重置状态
            //                                         // 检查是否已清空
            //         if (received_answer_stream.str().empty())
            //         {
            //             std::cout << "receive stringstream is empty" << std::endl;
            //         }
            //         // 解算 answer
            //         ThreadPool pool(numThreads);
            //         for (size_t i = 0; i < sketch_num; i++) // 文件中Sketch的个数
            //         {
            //             size_t st_load_index = i * (SketchLength + Header_db) + Header_db;
            //             size_t hash_index = (st_load_index / (SketchLength + Header_db)) % HashNum;
            //             size_t db_index = st_load_index / ((SketchLength + Header_db) * HashNum);
            //             size_t query_i = 0;
            //             pool.enqueue(std::bind(client_subanswer,
            //                                    ref(decryptor), ref(chunk_num), ref(Encrypted_Result[i]),
            //                                    ref(encoder), ref(slot_count), ref(hash_index), ref(db_index),
            //                                    ref(query_i), ref(query_card), ref(out_dir), ref(SketchLength)));
            //         }
            //         // 等待所有任务完成
            //         pool.wait();
            //         phase++;
            //         std::string response = "answer decoded!";
            //         // cout << response << endl;
            //         auto tmp = end4;
            //         end4 = high_resolution_clock::now();                // 获取结束时间点
            //         duration = duration_cast<milliseconds>(end4 - tmp); // 计算运行时间
            //         cout << "7. decode answer:" << duration.count() / 1000.0 << " 秒" << endl;
            //         auto p_end = high_resolution_clock::now();                      // 获取结束时间点
            //         auto p_duration = duration_cast<milliseconds>(p_end - p_start); // 计算运行时间
            //         cout << "******************************************************" << endl;
            //         cout << "\tDB record number:" << sketch_num / HashNum << endl;
            //         cout << "\tHASH size:" << SketchLength << endl;
            //         cout << "\tHASH number:" << HashNum << endl;
            //         cout << "\tTOTAL runtime:" << p_duration.count() / 1000.0 << "s" << endl;
            //         cout << "******************************************************" << endl;
            //     }
            // continue;
            // }
        }
        else
        {
            std::cout << "请输入消息: ";
            std::string message;
            std::getline(std::cin, message);

            // 发送消息给服务器
            if (send(clientSocket, message.c_str(), message.length(), 0) < 0)
            {
                std::cerr << "发送消息失败" << std::endl;
                break;
            }
            phase++;
        }
        memset(buffer, 0, sizeof(buffer));
        // 接收服务器响应
        if (recv(clientSocket, buffer, sizeof(buffer), 0) < 0)
        {
            std::cerr << "接收响应失败" << std::endl;
            break;
        }
        if (std::strcmp(buffer, OK) != 0)
        {
            std::cout << "服务器响应: " << buffer << std::endl;
        }
    }

    // 关闭套接字
    close(clientSocket);

    return 0;
}
