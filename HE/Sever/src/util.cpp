#include "util.h"
#include <iomanip>

// C++ 文件中声明被覆盖的 C 函数
extern "C"
{
    // 被覆盖的 C 函数声明
    int close(int __fd);
}

void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    case seal::scheme_type::bgv:
        scheme_name = "BGV";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}

// 获取当前进程的内存占用大小（单位：KB）
double getCurrentProcessMemoryUsage()
{
    rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return (double)usage.ru_maxrss;
}

void query_make(vector<vector<double>> &query, vector<double> &query_idx)
{
    for (auto i = query_idx.begin(); i != query_idx.end(); i++)
    {
        query[(*i) / query[0].size()][(uint32_t(*i)) % query[0].size()] = 1;
    }
    // int k = 0;
    // for (auto i = query.begin(); i != query.end(); i++)
    // {
    //     cout << "idx:" << k << "\tquery[idx++]:" << *i << "\tLEN:" << SketchLength << endl;
    //     k++;
    // }
}

void dataload(std::string &path, size_t &st_load_index, size_t &SketchLength, vector<vector<double>> &db)
{
    /*
       st_load_index: 从文件中读取数据的起始下标（bit单位） st_load_index = i* SketchLength 第i个Sketch
       Note： 如果SketchLength不能被8整除，那么需要做特别处理，读取的长度大于SketchLength/8 !!!!!
    */
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file.\n";
    }

    file.seekg(st_load_index / 8, std::ios::beg);
    uint64_t sketch_size_byte = SketchLength / 8;
    if (SketchLength % 8 != 0)
    {
        cout << "warning: SketchLength % 8 != 0." << endl;
    }
    char *buffer = new char[sketch_size_byte];
    file.read(buffer, sketch_size_byte);
    file.close();

    uint64_t idx = 0;
    uint64_t sum = 0;
    // 使用buffer数组进行后续处理，例如打印每个字节的值
    for (int i = 0; i < sketch_size_byte; i++)
    {
        for (int j = 0; j <= 7; j++)
        {
            db[idx / db[0].size()][idx % db[0].size()] = double((buffer[i] >> j) & 1);
            sum += double((buffer[i] >> j) & 1);
            if ((idx + 1) % db[0].size() == 0)
            {
                /*
                    在SEAL库中，当使用CKKS方案时，加密明文值为0的密文向量可能会导致错误。
                    这是因为CKKS方案使用的是浮点数加密方法，而浮点数的精度在0附近会变得非常低。
                    因此，对于密文向量中的所有值都为0的情况，SEAL库无法确定结果精确的数量级和值，从而导致错误。
                */
                if (sum == 0)
                {
                    db[idx / db[0].size()][idx % db[0].size()] = 1;
                }
                else
                {
                    sum = 0;
                }
            }
            idx++;
        }
        if (sum == 0) // sketch最后一个slot没填满，并且填入的均为0
        {
            db[idx / db[0].size()][idx % db[0].size()] = 1;
        }
    }
    // int data = 0;
    // for (int i = 0; i < 8*8; i++)
    // {
    //     data += int(db[0][i]) << (i % 4);
    //     if ((i + 1) % 4 == 0)
    //     {
    //         cout << std::hex << data << endl;
    //         data = 0;
    //     }
    // }

    delete[] buffer;
}

void db_encode(CKKSEncoder &encoder, uint32_t &chunk_num, vector<vector<double>> &db,
               double &scale, vector<Plaintext> &DB_Plain)
{
    for (int j = 0; j < chunk_num; j++)
    {
        encoder.encode(db[j], scale, DB_Plain[j]);
    }
}

void multiply_db_query(Evaluator &evaluator, uint32_t &chunk_num, vector<Ciphertext> &query_encrypted,
                       vector<Plaintext> &DB_Plain, vector<Ciphertext> &Encrypted_Result)
{
    for (int j = 0; j < chunk_num; j++)
    {
        // cout << "multiply_plain idex:" << i << endl;
        evaluator.multiply_plain(query_encrypted[j], DB_Plain[j], Encrypted_Result[j]);
        evaluator.rescale_to_next_inplace(Encrypted_Result[j]);
    }
}

void decrypt_result(Decryptor &decryptor, uint32_t &chunk_num, vector<Ciphertext> &Encrypted_Result,
                    vector<Plaintext> &Plain_Result)
{
    for (int j = 0; j < chunk_num; j++)
    {
        decryptor.decrypt(Encrypted_Result[j], Plain_Result[j]);
    }
}

void decode_result(CKKSEncoder &encoder, uint32_t &chunk_num, vector<Plaintext> &Plain_Result,
                   vector<vector<double>> &Result_Vector)
{
    for (int j = 0; j < chunk_num; j++)
    {
        encoder.decode(Plain_Result[j], Result_Vector[j]);
    }
}

size_t file_byte_length(std::string path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file.\n";
    }
    file.seekg(0, std::ios::end);
    const size_t file_size = file.tellg(); // 字节为单位
    file.close();
    return file_size;
}

std::vector<std::string> get_query_path(std::string &query_dir)
{
    std::vector<std::string> lines;
    std::ifstream file(query_dir);

    if (file.is_open())
    {
        std::string line;

        while (std::getline(file, line))
        {
            lines.push_back(line);
        }

        file.close();
    }
    else
    {
        std::cerr << "Failed to open file: " << query_dir << std::endl;
    }

    return lines;
}

// 将vector<vector<Ciphertext>>类型的数据结构序列化为字符串
std::string serializeData(const std::vector<std::vector<seal::Ciphertext>> &data)
{
    std::string serializedData;

    // 获取data的维度信息
    size_t numRows = data.size();
    size_t numCols = (numRows > 0) ? data[0].size() : 0;

    // 序列化维度信息
    serializedData += std::to_string(numRows) + ",";
    serializedData += std::to_string(numCols) + ",";

    // 序列化每个Ciphertext对象的数据
    for (const auto &row : data)
    {
        for (const auto &cipher : row)
        {
            std::stringstream ss;
            cipher.save(ss); // 保存Ciphertext到字符串流
            std::string cipherStr = ss.str();
            serializedData += cipherStr + ";";
        }
    }

    return serializedData;
}

// 将字符串反序列化为vector<vector<Ciphertext>>类型的数据结构
std::vector<std::vector<seal::Ciphertext>> deserializeData(const std::string &serializedData, SEALContext &context)
{
    std::vector<std::vector<seal::Ciphertext>> data;

    size_t pos = 0;
    size_t delimPos;

    // 解析维度信息
    delimPos = serializedData.find(",");
    size_t numRows = std::stoi(serializedData.substr(pos, delimPos));
    pos = delimPos + 1;

    delimPos = serializedData.find(",", pos);
    size_t numCols = std::stoi(serializedData.substr(pos, delimPos));
    pos = delimPos + 1;

    data.resize(numRows, std::vector<seal::Ciphertext>(numCols));
    // 解析每个Ciphertext对象的数据
    for (size_t i = 0; i < numRows; i++)
    {
        for (size_t j = 0; j < numCols; j++)
        {
            delimPos = serializedData.find(";", pos);
            std::string cipherStr = serializedData.substr(pos, delimPos - pos);
            cout << "pos:" << pos << "delimPos:" << delimPos << "delimPos - pos:" << delimPos - pos << endl;
            pos = delimPos + 1;
            std::stringstream ss(cipherStr);
            seal::Ciphertext cipher;
            cipher = seal::Ciphertext(context); // 使用正确的上下文构造空的Ciphertext对象
            cipher.load(context, ss);           // 从字符串流加载Ciphertext
            data[i][j] = cipher;
        }
    }
    cout << "3333333333333" << endl;
    return data;
}

void socketTask(int &sever_socketId, int &ansPort, int &client_socketId,
                size_t st_index, int last_socket, size_t answer_send_cnt, size_t &RECEIVE_CACHE, size_t &BUFFER_SIZE,
                std::string &serializedData)
{
    char *buffer = new char[BUFFER_SIZE];
    // 创建套接字
    sever_socketId = socket(AF_INET, SOCK_STREAM, 0);
    if (sever_socketId == -1)
    {
        perror("Error creating socket");
        return;
    }
    // 设置套接字地址
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ansPort);
    addr.sin_addr.s_addr = INADDR_ANY;

    // 绑定套接字到端口
    // 将套接字与服务器地址绑定
    if (bind(sever_socketId, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        std::cerr << "绑定套接字失败" << std::endl;
        close(sever_socketId);
        return;
    }

    // 监听客户端连接
    cout << "开始监听 port:" << ansPort << endl;
    if (listen(sever_socketId, 10) < 0)
    {
        std::cerr << "监听失败, sever_socketId, port: " << ansPort << std::endl;
        close(sever_socketId);
        return;
    }
    std::cout << "Server listening on port " << ansPort << std::endl;

    // 接受客户端连接
    struct sockaddr_in clientAddress;
    socklen_t clientAddressLength = sizeof(clientAddress);
    client_socketId = accept(sever_socketId, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (client_socketId < 0)
    {
        std::cerr << "接受连接失败, sever_socketId, prot: " << ansPort << std::endl;
        close(sever_socketId);
        return;
    }

    cout << "ans port: " << ansPort << " has initialized." << endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    size_t answer_sended_cnt = 0;
    while (true)
    {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead;
        bytesRead = recv(client_socketId, buffer, BUFFER_SIZE, 0);
        // cout << "客户端发来消息：" << string(buffer, bytesRead) << endl;
        if (bytesRead == -1)
        {
            // 处理接收错误的情况
            break;
        }
        else if (bytesRead == 0)
        {
            // 连接已关闭，接收完成
            cout << "error !!!!!" << endl;
            break;
        }
        else
        {
            // cout << "answer_send_cnt: " << answer_send_cnt << "\tanswer_sended_cnt: " << answer_sended_cnt << endl;
            if (answer_sended_cnt < answer_send_cnt) // query发送
            {
                // std::this_thread::sleep_for(std::chrono::milliseconds(3000));

                // if (send(client_socketId, to_string(answer_sended_cnt).c_str(), to_string(answer_sended_cnt).length(), 0) < 0)
                // {
                //     std::cerr << "测试发送失败" << std::endl;
                //     break;
                // }
                // answer_sended_cnt++;
                // continue;

                // 发送序列化后的数据给服务器
                if (send(client_socketId, serializedData.substr(st_index + answer_sended_cnt * RECEIVE_CACHE, RECEIVE_CACHE).c_str(), RECEIVE_CACHE, 0) < 0)
                {
                    if (serializedData.size() >= (st_index + answer_sended_cnt * RECEIVE_CACHE + RECEIVE_CACHE))
                    {
                        // cout << "Yes, range lawful." << endl;
                    }
                    else
                    {
                        cout << "No, index out of range." << endl;
                    }

                    std::cerr << "1发送encrypted answer数据失败" << std::endl;
                    break;
                }
                answer_sended_cnt++;
            }
            else if (answer_sended_cnt == answer_send_cnt) // query发送完毕
            {
                if (last_socket)
                {
                    // cout << "port:" << ansPort << "\ttail: !!!!!!!!!!!!!!!!!!!!!!!!!!!" << endl;
                    // cout << "tail length:" << serializedData.length() % RECEIVE_CACHE << endl;
                    // 发送序列化后的数据给服务器
                    if (send(client_socketId, serializedData.substr(st_index + answer_sended_cnt * RECEIVE_CACHE).c_str(), serializedData.length() % RECEIVE_CACHE, 0) < 0)
                    {
                        std::cerr << "2发送encrypted answer失败" << std::endl;
                        break;
                    }
                }
                else
                {
                    // cout << "port:" << ansPort << " is not tail." << endl;
                    // cout << "port:" << ansPort << "\tsize:" << serializedData.size() << "\t index:" << st_index + answer_sended_cnt * RECEIVE_CACHE + RECEIVE_CACHE << endl;
                    // cout << "port:" << ansPort << "\tanswer_sended_cnt:" << answer_sended_cnt << "\tst_index:" << st_index << endl;
                    if (send(client_socketId, serializedData.substr(st_index + answer_sended_cnt * RECEIVE_CACHE, RECEIVE_CACHE).c_str(), RECEIVE_CACHE, 0) < 0)
                    {
                        std::cerr << "3发送encrypted answer数据失败" << std::endl;
                        break;
                    }
                }
                cout << "ans port: " << ansPort << "has sent the ciphertext." << endl;
                delete[] buffer;
                break;
            }
        }
    }
}