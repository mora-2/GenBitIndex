#ifndef SESSION_H
#define SESSION_H

#include <chrono>
#include "seal/seal.h"
#include "util.h"
#include <iostream>
#include <fstream>

using namespace std;
using namespace chrono;
using namespace seal;

void client_makequery(CKKSEncoder &encoder, uint32_t chunk_num, uint32_t slot_count, double scale,
                      vector<double> &query_idx,
                      Encryptor &encryptor, vector<Ciphertext> &query_encrypted);

void client_query_read(CKKSEncoder &encoder, uint32_t chunk_num, uint32_t slot_count, double scale,
                       string query_path, size_t &query_i, size_t &query_card, string &out_dir, size_t &SketchLength, size_t &HashNum,
                       Encryptor &encryptor, vector<vector<Ciphertext>> &query_encrypted);

void sever_subtask(std::string &path, size_t &st_load_index, size_t &SketchLength, uint32_t &chunk_num, uint32_t &slot_count,
                   CKKSEncoder &encoder, double &scale,
                   Evaluator &evaluator, vector<Ciphertext> &query_encrypted,  std::stringstream &answer_stream,
                   size_t sketch_index, size_t &db_index,
                   size_t query_i, size_t &query_card, string &out_dir);

void client_subanswer(Decryptor &decryptor, uint32_t &chunk_num, vector<Ciphertext> &Encrypted_Result,
                      CKKSEncoder &encoder, uint32_t &slot_count, size_t &sketch_index, size_t &db_index,
                      size_t &query_i, size_t &query_card, string &out_dir, size_t &SketchLength);

#endif /*SESSION_H*/