#include "session.h"

/*
    client_makequery:
        1. get query_array
        2. query encode
        3. query encrypt
*/
void client_makequery(CKKSEncoder &encoder, uint32_t chunk_num, uint32_t slot_count, double scale,
                      vector<double> &query_idx,
                      Encryptor &encryptor, vector<Ciphertext> &query_encrypted)
{
    // 1. get query_array
    vector<vector<double>> query(chunk_num, vector<double>(slot_count));
    query_make(query, query_idx);

    // 2. query encode
    auto start = high_resolution_clock::now(); // 获取开始时间点
    vector<Plaintext> query_plain(chunk_num);
    for (int i = 0; i < chunk_num; i++)
    {
        encoder.encode(query[i], scale, query_plain[i]);
    }

    auto end = high_resolution_clock::now();                  // 获取结束时间点
    auto duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    cout << "Encode query vectors.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;

    // 3. query encrypt
    start = high_resolution_clock::now(); // 获取开始时间点
    for (int i = 0; i < chunk_num; i++)
    {
        encryptor.encrypt(query_plain[i], query_encrypted[i]);
    }

    end = high_resolution_clock::now();                  // 获取结束时间点
    duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    cout << "Encrypt query vectors.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;
}

void client_query_read(CKKSEncoder &encoder, uint32_t chunk_num, uint32_t slot_count, double scale,
                       string query_path, size_t &query_i, size_t &query_card, string &out_dir, size_t &SketchLength, size_t &HashNum,
                       Encryptor &encryptor, vector<vector<Ciphertext>> &query_encrypted)
{

    for (int hash_index = 0; hash_index < HashNum; hash_index++)
    {
        std::ofstream outfile(out_dir + "/query_result.csv", ios::app); // 打开文件
        outfile << query_card << ",";
        outfile << query_i << ",";
        outfile << hash_index << ",";
        // 1. get query_array
        vector<vector<double>> query(chunk_num, vector<double>(slot_count, 0));
        size_t st_index = hash_index * SketchLength;
        dataload(query_path, st_index, SketchLength, query);

        // 2. query encode
        auto start = high_resolution_clock::now(); // 获取开始时间点
        vector<Plaintext> query_plain(chunk_num);
        for (int i = 0; i < chunk_num; i++)
        {
            encoder.encode(query[i], scale, query_plain[i]);
        }

        auto end = high_resolution_clock::now();                  // 获取结束时间点
        auto duration = duration_cast<milliseconds>(end - start); // 计算运行时间
        // outfile << "Encode query vectors.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;
        outfile << duration.count() / 1000.0 << ",";

        // 3. query encrypt
        start = high_resolution_clock::now(); // 获取开始时间点
        for (int i = 0; i < chunk_num; i++)
        {
            encryptor.encrypt(query_plain[i], query_encrypted[hash_index][i]);
        }

        end = high_resolution_clock::now();                  // 获取结束时间点
        duration = duration_cast<milliseconds>(end - start); // 计算运行时间
        outfile << duration.count() / 1000.0 << endl;
        outfile.close();
        // outfile << "Encrypt query vectors.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;
        // outfile << "query hash_index:" << hash_index << endl;
        cout << "query_cardinality:" << query_card << "\tquery_i:" << query_i << "\tquery hash_index: " << hash_index << " finished." << endl;
    }
}

/*
    sever_subtask:
        1. read db's record
        2. encode record
        3. mutiply record with encrypted query
        4. return encrypted result
*/
void sever_subtask(std::string &path, size_t &st_load_index, size_t &SketchLength, uint32_t &chunk_num, uint32_t &slot_count,
                   CKKSEncoder &encoder, double &scale,
                   Evaluator &evaluator, vector<Ciphertext> &query_encrypted, std::stringstream &answer_stream,
                   size_t sketch_index, size_t &db_index,
                   size_t query_i, size_t &query_card, string &out_dir)
{
    // write some info
    std::ofstream outfile(out_dir + "/db_" + std::to_string(db_index) + "_query_card_" + std::to_string(query_card) +
                              "_query_" + std::to_string(query_i) + "_sketch_" + std::to_string(sketch_index) + "_result.csv",
                          ios::app); // 打开文件

    outfile << query_card << ",";
    outfile << query_i << ",";
    outfile << db_index << ",";
    outfile << sketch_index << ",";

    // 1. read db's record
    auto start = high_resolution_clock::now(); // 获取开始时间点
    vector<vector<double>> db(chunk_num, vector<double>(slot_count, 0));
    dataload(path, st_load_index, SketchLength, db);

    auto end = high_resolution_clock::now();                  // 获取结束时间点
    auto duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    outfile << duration.count() / 1000.0 << ",";
    // outfile << "read single db vectors.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;

    // 2. encode record
    start = high_resolution_clock::now(); // 获取开始时间点
    vector<Plaintext> DB_Plain(chunk_num);
    db_encode(encoder, chunk_num, db, scale, DB_Plain);

    end = high_resolution_clock::now();                  // 获取结束时间点
    duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    outfile << duration.count() / 1000.0 << ",";
    // outfile << "encode single db vectors.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;

    // 3. mutiply record with encrypted query
    start = high_resolution_clock::now(); // 获取开始时间点
                                          // multiply_db_query(evaluator, chunk_num, query_encrypted,
                                          //                   DB_Plain, Encrypted_Result);
    Ciphertext result_multiply;
    for (int j = 0; j < chunk_num; j++)
    {
        if (j == 0)
        {
            evaluator.multiply_plain(query_encrypted[j], DB_Plain[j], result_multiply);
            evaluator.rescale_to_next_inplace(result_multiply);
        }
        else
        {
            Ciphertext tmp_cipher;
            // cout << "multiply_plain idex:" << i << endl;
            evaluator.multiply_plain(query_encrypted[j], DB_Plain[j], tmp_cipher);
            evaluator.rescale_to_next_inplace(tmp_cipher);
            evaluator.add(result_multiply, tmp_cipher, result_multiply);
        }
    }
    result_multiply.save(answer_stream);

    end = high_resolution_clock::now();                  // 获取结束时间点
    duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    outfile << duration.count() / 1000.0 << ",";
    // outfile << "multiply_plain.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;

    // 4. return encrypted result
    // 通过引用返回Encrypted_Result

    // 关闭文件
    outfile.close();
}

/*
    client_subanswer:
        1. decrypt the received sever's result
        2. decode the plain result
        3. sum up the result, which is in the form of chunks
        4. save to file
*/
void client_subanswer(Decryptor &decryptor, uint32_t &chunk_num, vector<Ciphertext> &Encrypted_Result,
                      CKKSEncoder &encoder, uint32_t &slot_count, size_t &sketch_index, size_t &db_index,
                      size_t &query_i, size_t &query_card, string &out_dir, size_t &SketchLength)
{
    // write some info
    std::ofstream outfile(out_dir + "/db_" + std::to_string(db_index) + "_query_card_" + std::to_string(query_card) +
                              "_query_" + std::to_string(query_i) + "_sketch_" + std::to_string(sketch_index) + "_result.csv",
                          ios::app); // 打开文件

    // 1. decrypt the received sever's result
    auto start = high_resolution_clock::now(); // 获取开始时间点
    vector<Plaintext> Plain_Result(chunk_num);
    decrypt_result(decryptor, chunk_num, Encrypted_Result, Plain_Result);

    auto end = high_resolution_clock::now();                  // 获取结束时间点
    auto duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    outfile << duration.count() / 1000.0 << ",";
    // outfile << "decrypt result vector.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;

    // 2. decode the plain result
    start = high_resolution_clock::now(); // 获取开始时间点
    vector<vector<double>> Result_Vector(chunk_num, vector<double>(slot_count));
    decode_result(encoder, chunk_num, Plain_Result, Result_Vector);

    end = high_resolution_clock::now();                  // 获取结束时间点
    duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    outfile << duration.count() / 1000.0 << ",";
    // outfile << "decode result vector.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;

    // 3. sum up the result, which is in the form of chunks
    start = high_resolution_clock::now(); // 获取开始时间点
    double Result(0);
    for (int j = 0; j < chunk_num; j++)
    {
        for (int k = 0; k < slot_count; k++)
        {
            Result += Result_Vector[j][k]; // add
        }
    }

    end = high_resolution_clock::now();                  // 获取结束时间点
    duration = duration_cast<milliseconds>(end - start); // 计算运行时间
    outfile << duration.count() / 1000.0 << ",";
    // outfile << "sum result vector.运行时间: " << duration.count() / 1000.0 << " 秒" << endl;

    // 4. save to file
    outfile << std::round(Result) << endl;

    // outfile << "result:" << std::round(Result) << "\tdb:" << db_index << "\tsketch:" << sketch_index << std::endl; // 写入文件
    outfile.close(); // 关闭文件
}