#include "task.h"

void thread_task(std::string &db_path, size_t st_load_index, size_t Header_db, size_t &SketchLength, uint32_t chunk_num, uint32_t slot_count,
                 CKKSEncoder &encoder, double scale,
                 Evaluator &evaluator, vector<vector<Ciphertext>> &query_encrypted,
                 Decryptor &decryptor, size_t HashNum,
                 size_t query_i, size_t query_card, string out_dir, size_t db_index)
{
    // vector<Ciphertext> Encrypted_Result(chunk_num);
    // size_t hash_index = (st_load_index / (SketchLength + Header_db)) % HashNum;
    // // size_t db_index = st_load_index / ((SketchLength + Header_db) * HashNum);
    // sever_subtask(db_path, st_load_index, SketchLength, chunk_num, slot_count,
    //               encoder, scale,
    //               evaluator, query_encrypted[hash_index], Encrypted_Result,
    //               hash_index, db_index,
    //               query_i, query_card, out_dir);
    // client_subanswer(decryptor, chunk_num, Encrypted_Result,
    //                  encoder, slot_count, hash_index, db_index,
    //                  query_i, query_card, out_dir, SketchLength);
    // cout <<"query:" << query_i<< "    db: " << db_index  << "    hash_index:" << hash_index << " compute finish." << endl;
}