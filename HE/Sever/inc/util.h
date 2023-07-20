#ifndef UTIL_H
#define UTIL_H

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <sys/resource.h>
#include "seal/seal.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;
using namespace seal;

double getCurrentProcessMemoryUsage();
void query_make(vector<vector<double>> &query, vector<double> &query_idx);
void dataload(std::string &path, size_t &st_load_index, size_t &SketchLength, vector<vector<double>> &db);
void db_encode(CKKSEncoder &encoder, uint32_t &chunk_num, vector<vector<double>> &db,
               double &scale, vector<Plaintext> &DB_Plain);
void multiply_db_query(Evaluator &evaluator, uint32_t &chunk_num, vector<Ciphertext> &query_encrypted,
                       vector<Plaintext> &DB_Plain, vector<Ciphertext> &Encrypted_Result);
void decrypt_result(Decryptor &decryptor, uint32_t &chunk_num,
                    vector<Ciphertext> &Encrypted_Result, vector<Plaintext> &Plain_Result);
void decode_result(CKKSEncoder &encoder, uint32_t &chunk_num, vector<Plaintext> &Plain_Result,
                   vector<vector<double>> &Result_Vector);
size_t file_byte_length(std::string path);
std::vector<std::string> get_query_path(std::string &query_dir);

void print_parameters(const seal::SEALContext &context);
std::string serializeData(const std::vector<std::vector<seal::Ciphertext>> &data);
std::vector<std::vector<seal::Ciphertext>> deserializeData(const std::string &serializedData, SEALContext &context);

void socketTask(int &sever_socketId, int &ansPort, int &client_socketId,
                size_t st_index, int last_socket, size_t answer_send_cnt,size_t &RECEIVE_CACHE,size_t &BUFFER_SIZE,
                std::string &serializedData);

#endif /*UTIL_H*/