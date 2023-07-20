#ifndef TASK_H
#define TASK_H

#include "session.h"

void thread_task(std::string &path, size_t st_load_index, size_t Header_db, size_t &SketchLength, uint32_t chunk_num, uint32_t slot_count,
                 CKKSEncoder &encoder, double scale,
                 Evaluator &evaluator, vector<vector<Ciphertext>> &query_encrypted,
                 Decryptor &decryptor, size_t HashNum,
                 size_t query_i, size_t query_card, string out_dir, size_t db_index);

#endif /*TASK_H*/