/**
 * @file db.cpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#include "dbsync.hpp"
#include "db.hpp"
#include "db_statements.hpp"
#include "fimDB.hpp"

#ifdef __cplusplus
extern "C" {
#endif
const char* SQL_STMT[] = {};
#ifdef WIN32
/**
 * @brief Function that looks for the separator `:` between keys and values in synchronization messages.
 *
 * @param input string with the path of the synchronization message.
 * @return char* Pointer to the separator. If the separator wasn't found, returns NULL.
 */
static char* find_key_value_limiter(char* input);

#endif

std::string CreateStatement()
{
    std::string ret = CREATE_FILE_DB_STATEMENT;
#ifdef WIN32
    ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
    ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
#endif

    return ret;
}

fdb_t* fim_db_init(int storage, void(*sync_callback)(const char* log, const char* tag), void(*loggFunction)(modules_log_level_t level, const char* log))
{

    std::string path = (storage == FIM_DB_MEMORY) ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH;
    auto handler_DBSync = std::make_shared<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path, CreateStatement());
    auto handler_RSync = std::make_shared<RemoteSync>();

    FIMDB::getInstance().init(syscheck.sync_interval, syscheck.file_limit, sync_callback, loggFunction, handler_DBSync, handler_RSync);

    return NULL;
}

void fim_db_close(fdb_t* fim_sql) {}
void fim_db_clean(void) {}

int fim_db_cache(fdb_t* fim_sql) {}

int fim_db_create_file(const char* path, const char* source, const int storage, sqlite3** fim_db) {}

fim_tmp_file* fim_db_create_temp_file(int storage) {}

void fim_db_clean_file(fim_tmp_file** file, int storage) {}

#ifndef WIN32
// LCOV_EXCL_START
fim_entry* fim_db_get_entry_from_sync_msg(fdb_t* fim_sql,
                                          __attribute__((unused)) fim_type type,
                                          const char* path) {}
// LCOV_EXCL_STOP
#else

static char* find_key_value_limiter(char* input) {}


fim_entry* fim_db_get_entry_from_sync_msg(fdb_t* fim_sql, fim_type type, const char* path)
{
}
#endif

int fim_db_finalize_stmt(fdb_t* fim_sql)
{
}

void fim_db_check_transaction(fdb_t* fim_sql)
{

}

void fim_db_force_commit(fdb_t* fim_sql)
{

}

int fim_db_clean_stmt(fdb_t* fim_sql, int index)
{
}

//wrappers

int fim_db_process_get_query(fdb_t* fim_sql,
                             __attribute__((unused)) int type,
                             int index,
                             void (*callback)(fdb_t*, fim_entry*, int, void*),
                             int storage,
                             void* arg)
{}

int fim_db_multiple_row_query(fdb_t* fim_sql, int index, void* (*decode)(sqlite3_stmt*), void (*free_row)(void*),
                              void (*callback)(fdb_t*, void*, int, void*), int storage, void* arg)
{}

int fim_db_exec_simple_wquery(fdb_t* fim_sql, const char* query)
{}

void fim_db_callback_save_string(__attribute__((unused))fdb_t* fim_sql, const char* str, int storage, void* arg)
{

}

void fim_db_callback_save_path(__attribute__((unused))fdb_t* fim_sql, fim_entry* entry, int storage, void* arg)
{

}

void fim_db_callback_calculate_checksum(__attribute__((unused)) fdb_t* fim_sql, char* checksum,
                                        __attribute__((unused))int storage, void* arg)
{

}

int _fim_db_get_count(fdb_t* fim_sql, int index)
{
}

int fim_db_get_count(fdb_t* fim_sql, int index)
{}

int fim_db_process_read_file(fdb_t* fim_sql,
                             fim_tmp_file* file,
                             __attribute__((unused)) int type,
                             pthread_mutex_t* mutex,
                             void (*callback)(fdb_t*, fim_entry*, pthread_mutex_t*, void*, void*, void*),
                             int storage,
                             void* alert,
                             void* mode,
                             void* w_evt)
{

}

// General use functions

void fim_db_bind_range(fdb_t* fim_sql, int index, const char* start, const char* top)
{

}

char* fim_db_decode_string(sqlite3_stmt* stmt)
{}

char** fim_db_decode_string_array(sqlite3_stmt* stmt)
{

}

int fim_db_get_string(fdb_t* fim_sql, int index, char** str)
{


}

int fim_db_get_last_path(fdb_t* fim_sql, int type, char** path)
{

}

// LCOV_EXCL_START
int fim_db_get_first_path(fdb_t* fim_sql, int type, char** path)
{}
// LCOV_EXCL_STOP

int fim_db_get_data_checksum(fdb_t* fim_sql, fim_type type, void* arg)
{}

int fim_db_get_count_range(fdb_t* fim_sql, fim_type type, const char* start, const char* top, int* count)
{}

int fim_db_get_checksum_range(fdb_t* fim_sql,
                              fim_type type,
                              const char* start,
                              const char* top,
                              int n,
                              EVP_MD_CTX* ctx_left,
                              EVP_MD_CTX* ctx_right,
                              char** str_pathlh,
                              char** str_pathuh){}

int fim_db_get_path_range(fdb_t* fim_sql,
                          fim_type type,
                          const char* start,
                          const char* top,
                          fim_tmp_file** file,
                          int storage)
{}

int fim_db_read_line_from_file(fim_tmp_file* file, int storage, int it, char** buffer)
{}

#ifndef WIN32
// LCOV_EXCL_START
int fim_db_get_count_entries(fdb_t* fim_sql)
{
    auto query = {R"({
                   "query":{"column_list":["count(*) AS count"],
                   "row_filter":"",
                   "distinct_opt":false,
                   "order_by_opt":"",
                   "count_opt":100}})"};
    return 0;
}
// LCOV_EXCL_STOP
#else
int fim_db_get_count_entries(fdb_t* fim_sql)
{}
#endif

int fim_db_is_full(fdb_t* fim_sql)
{}
#ifdef __cplusplus
}
#endif
