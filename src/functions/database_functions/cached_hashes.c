#include "cached_hashes.h"

#include <stdio.h>
#include <time.h>

#include "define_macro_functions.h"
#include "define_macros.h"

// TODO move all db operations to lates functions from xcash_db_operations
// TODO don't forget to add indexes to hashes2 by 'hash'
int get_data(mongoc_client_t *client, const char *db_name, const char *field_name, char *data)
{
    bson_t *query;
    bson_t *opts;
    mongoc_collection_t *collection;

    mongoc_cursor_t *cursor;
    const bson_t *doc;
    bson_iter_t iter;
    bson_iter_t field;
    int result = -1;
    uint32_t len = 0;

    collection = mongoc_client_get_collection(client, database_name, "hashes2");
    query = BCON_NEW("db_name", db_name);

    opts = BCON_NEW("projection", "{",
                    field_name, BCON_BOOL(true),
                    "_id", BCON_BOOL(false),
                    "}");

    cursor = mongoc_collection_find_with_opts(collection, query, opts, NULL);

    while (mongoc_cursor_next(cursor, &doc))
    {
        if (bson_iter_init(&iter, doc) && bson_iter_find_descendant(&iter, field_name, &field) && BSON_ITER_HOLDS_UTF8(&field))
        {
            strcpy(data, bson_iter_utf8(&field, &len));
            result = 0;
        }
    }

    bson_destroy(query);
    bson_destroy(opts);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);

    return result;
}

int get_db_hashes(mongoc_client_t *client, const char *db_name, char *hash, char *db_hash)
{
    bson_t *query;
    bson_t *opts;
    mongoc_collection_t *collection;

    mongoc_cursor_t *cursor;
    const bson_t *doc;
    bson_iter_t iter;
    bson_iter_t field;
    int result = -1;
    uint32_t len = 0;

    collection = mongoc_client_get_collection(client, database_name, "hashes2");

    query = BCON_NEW("db_name", db_name);

    opts = BCON_NEW("projection", "{",
                    "hash", BCON_BOOL(true),
                    "db_hash", BCON_BOOL(true),
                    "_id", BCON_BOOL(false),
                    "}");

    cursor = mongoc_collection_find_with_opts(collection, query, opts, NULL);

    while (mongoc_cursor_next(cursor, &doc))
    {
        result = 0;
        if (bson_iter_init(&iter, doc) && bson_iter_find_descendant(&iter, "hash", &field) && BSON_ITER_HOLDS_UTF8(&field))
        {
            strcpy(hash, bson_iter_utf8(&field, &len));
        }
        else
        {
            result = -2;
            ERROR_PRINT("Failed to parse hash for %s", db_name);
        }

        if (result == 0 && bson_iter_init(&iter, doc) && bson_iter_find_descendant(&iter, "db_hash", &field) && BSON_ITER_HOLDS_UTF8(&field))
        {
            strcpy(db_hash, bson_iter_utf8(&field, &len));
        }
        else
        {
            result = -3;
            ERROR_PRINT("Failed to parse db_hash for %s", db_name);
        }
    }

    bson_destroy(query);
    bson_destroy(opts);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);

    return result;
}

/// @brief Calculate the md5 hash of the given db
/// @param client 
/// @param db_name 
/// @param hash pointer to 128 bytes zero padded md5 hash
/// @param db_hash pointer to 32 bytes short md5 hash
/// @return 0 if successful <0 error code otherwise
int calc_db_hashes(mongoc_client_t *client, const char *db_name, char *hash, char *db_hash)
{
    mongoc_collection_t *collection;
    mongoc_cursor_t *cursor;

    bson_t *query;
    const bson_t *doc = NULL;

    MD5_CTX md5;
    unsigned char md5_bin[16];

    int result = 0;

    collection = mongoc_client_get_collection(client, database_name, db_name);

    query = bson_new ();
    // suppress '_id' output to result data and sort by _id
    bson_t *opts = BCON_NEW("projection", "{", "_id", BCON_BOOL(false), "}","sort", "{", "_id", BCON_INT32 (1), "}");

    // Find documents
    cursor = mongoc_collection_find_with_opts(collection, query, opts, NULL);
    // clean it immediately
    bson_destroy(opts);

    MD5_Init(&md5);

    while (mongoc_cursor_next(cursor, &doc)) {
            char *str = bson_as_canonical_extended_json(doc, NULL);
            MD5_Update(&md5, str, strlen(str));
            bson_free(str);
    }
    MD5_Final(md5_bin, &md5);

    // make md5 hex string
    bin_to_hex(md5_bin, sizeof(md5_bin), db_hash); 

    // padding with zeroes
    memset(hash, '0', 96);
    // copy md5 hash including \0
    strcpy(hash + 96, db_hash);

    // cleanup
    bson_destroy(query);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    return result;
}


// FIXME don't store hash of empty collection. this could be potentially dangerous
int update_hashes(mongoc_client_t *client, const char *db_name, const char *hash, const char *db_hash)
{
    bson_t *filter;
    bson_t *update;
    bson_t *opts;
    mongoc_collection_t *collection;

    bson_error_t error;
    int result = 0;

    // don't store hashes for empty collection
    if (strcmp(db_hash, "d41d8cd98f00b204e9800998ecf8427e") == 0) {
        return 0;
    }

    collection = mongoc_client_get_collection(client, database_name, "hashes2");

    filter = BCON_NEW("db_name", db_name);

    opts = BCON_NEW("upsert", BCON_BOOL(true));

    update = BCON_NEW("$set",
                      "{",
                      "db_hash",
                      BCON_UTF8(db_hash),
                      "hash",
                      BCON_UTF8(hash),
                      "}");

    if (!mongoc_collection_update_one(collection, filter, update, opts, NULL, &error))
    {
        ERROR_PRINT("Update hashes %s failed %s", db_name, error.message);
        result = -1;
    }

    bson_destroy(filter);
    bson_destroy(update);
    bson_destroy(opts);
    mongoc_collection_destroy(collection);

    return result;
}

int get_hash(mongoc_client_t *client, const char *db_name, char *hash)
{
    char l_hash[129];
    char l_db_hash[33];
    int result = 0;

    struct timeval start_time, current_time, result_time;

    // start measuring
    gettimeofday(&start_time, NULL);


    pthread_mutex_lock(&hash_mutex);

    result = get_data(client, db_name, "hash", hash);
    if (result != 0)
    {
        // DEBUG_PRINT("Missed hash for %s recalculating...", db_name);
        // recalculate hashes
        result = calc_db_hashes(client, db_name, l_hash, l_db_hash);
        if (result != 0) {
            pthread_mutex_unlock(&hash_mutex);
            return -1;
        }

        // and now update hashes
        result = update_hashes(client, db_name, l_hash, l_db_hash);
        if (result != 0) {
            pthread_mutex_unlock(&hash_mutex);
            return -2;
        }

        gettimeofday(&current_time, NULL);
        timersub(&current_time, &start_time, &result_time);
        // DEBUG_PRINT("Missed hash for %s recalculation takes %ld.%06ld sec", db_name, (long int)result_time.tv_sec, (long int)result_time.tv_usec);

        strcpy(hash, l_hash);
    }
    else
    {
        //     PRINT_DEBUG("Hash hit cache for %s\n", db_name);
    }

    pthread_mutex_unlock(&hash_mutex);

    return result;
}

int get_dbhash(mongoc_client_t *client, const char *db_name, char *db_hash)
{
    char l_hash[129];
    char l_db_hash[33];
    int result = 0;

    struct timeval start_time, current_time, result_time;

    // start measuring
    gettimeofday(&start_time, NULL);


    result = get_data(client, db_name, "db_hash", db_hash);
    if (result != 0)
    {
        pthread_mutex_lock(&hash_mutex);

        // TODO check the performance of the solution
        // dirty fix for concurency problem 
        // if we got multiple requests to missed hash, only the first makes a calculation
        // that's why we need to recheck the hash
        // but the cons of that, we'll reread the db in case of missed hash
        result = get_data(client, db_name, "db_hash", db_hash);
        if (result == 0) {

            pthread_mutex_unlock(&hash_mutex);
            return result;
        }



        // PRINT_ERROR("Missed hash for %s recalculating\n", db_name);

        // recalculate hashes
        result = calc_db_hashes(client, db_name, l_hash, l_db_hash);
        if (result != 0) {
            pthread_mutex_unlock(&hash_mutex);
            return -1;
        }

        // and now update hashes
        result = update_hashes(client, db_name, l_hash, l_db_hash);
        if (result != 0) {
            pthread_mutex_unlock(&hash_mutex);
            return -2;
        }

        gettimeofday(&current_time, NULL);
        timersub(&current_time, &start_time, &result_time);
        // DEBUG_PRINT("Missed hash for %s recalculation takes %ld.%06ld sec", db_name, (long int)result_time.tv_sec, (long int)result_time.tv_usec);

        strcpy(db_hash, l_db_hash);
        
        pthread_mutex_unlock(&hash_mutex);

    }
    else
    {
        //     PRINT_DEBUG("Hash hit cache for %s\n", db_name);
    }


    return result;
}

int del_hash(mongoc_client_t *client, const char *db_name)
{
    mongoc_collection_t *collection;
    bson_error_t error;
    bson_t *filter;
    int result = 0;

    collection = mongoc_client_get_collection(client, database_name, "hashes2");

    filter = BCON_NEW("db_name", db_name);

    if (!mongoc_collection_delete_one(
            collection, filter, NULL, NULL, &error))
    {
        ERROR_PRINT("Delete hashes %s failed: %s", db_name, error.message);
        result = -1;
    }

    bson_destroy(filter);
    mongoc_collection_destroy(collection);
    if (test_settings == 0 && debug_settings == 1)
    {
    //   PRINT_DEBUG("Hash been deleted for %s\n", db_name);
    }


    const char *db_check1 = "reserve_proofs";
    const char *db_check2 = "reserve_bytes";

    // delete multicahe if single cache changed
    if (strstr(db_name, db_check1) && (strcmp(db_name, db_check1)!=0))
    {
        result = del_hash(client, db_check1);
    }else if (strstr(db_name, db_check2) && (strcmp(db_name, db_check2)!=0)) {
        result = del_hash(client, db_check2);
    }

    return result;
}

int drop_all_hashes(mongoc_client_t *client)
{
    mongoc_collection_t *collection;
    bson_error_t error;
    int result = 0;

    collection = mongoc_client_get_collection(client, database_name, "hashes2");

    if (!mongoc_collection_drop_with_opts(
            collection, NULL, &error))
    {
        ERROR_PRINT("Drop hashes failed: %s", error.message);
        result = -1;
    }

    mongoc_collection_destroy(collection);
    DEBUG_PRINT("All hashes are been dropped\n");

    return result;
}

void bin_to_hex(const unsigned char *bin_data, int data_size, char *buf)
{
    const char *hex = "0123456789abcdef";

    const unsigned char *p_in = bin_data;
    char *p_out = buf;
    int bin_size = data_size;
    while (bin_size-- > 0)
    {
        *p_out++ = hex[(*p_in >> 4) & 0xF];
        *p_out++ = hex[*p_in & 0xF];
        p_in++;
    }
    *p_out = 0;
}

void md5_hex(const char *src, char *dest)
{
    MD5_CTX md5;
    unsigned char md5_bin[16];

    MD5_Init(&md5);
    MD5_Update(&md5, src, strlen(src));
    MD5_Final(md5_bin, &md5);

    bin_to_hex(md5_bin, sizeof(md5_bin), dest);
}

// compare strings function
int cmpfunc(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

int calc_multi_hash(mongoc_client_t *client, const char *db_prefix, int max_index, char *hash)
{
    MD5_CTX md5;
    struct timeval start_time, last_time, current_time, tmp_time;

    char l_db_hash[33];
    unsigned char md5_bin[16];
    int result = 0;

    // array of db index names for sorting
    char(*names_array)[MAXIMUM_NUMBER_SIZE];

    // this is more than enough for name+index
    char db_name[64];

    // check for cached multi hash first
    if (get_data(client, db_prefix, "hash", hash) == 0)
    {
        return 0;
    }

    // otherwise recalculate the hash


    // start measuring
    gettimeofday(&start_time, NULL);
    last_time = start_time;


    names_array = calloc(max_index, MAXIMUM_NUMBER_SIZE);
    for (int i = 0; i < max_index; i++)
    {
        snprintf(names_array[i], MAXIMUM_NUMBER_SIZE, "%d", i + 1);
    }

    // we need to sort by indexes accodding to mongodb algorithm
    // like: 1,2,3,4,5,6,7,8,9,10,11 -> 1,10,11,2,3,4,5,6,7,8,9
    qsort(names_array, max_index, MAXIMUM_NUMBER_SIZE, cmpfunc);

    MD5_Init(&md5);
    for (int i = 0; i < max_index; i++)
    {
        gettimeofday(&current_time, NULL);
        timersub(&current_time, &last_time, &tmp_time);
        if (tmp_time.tv_sec > 2) {
            INFO_PRINT("Looks like the recalculation of hashes is taking some time [%d/%d]", i, max_index);
            last_time = current_time;
        }


        snprintf(db_name, sizeof(db_name), "%s_%s", db_prefix, names_array[i]);
        if (get_dbhash(client, db_name, l_db_hash) != 0)
        {
            ERROR_PRINT("Error getting hash for %s", db_name);
            result = -1;
            break;
        }
        MD5_Update(&md5, l_db_hash, strlen(l_db_hash));
    }
    MD5_Final(md5_bin, &md5);
    memset(hash, '0', 96);
    bin_to_hex(md5_bin, sizeof(md5_bin), hash + 96);    

    free(names_array);

    // update multihash
    result = update_hashes(client, db_prefix, hash, hash + 96);
    if (result != 0) {
        return -2;
    }


    return result;
}

// 0 - ok, <0 error
int get_multi_hash(mongoc_client_t *client, const char *db_prefix, char *hash)
{

    int result;
    size_t reserve_bytes_index;

    if (strcmp(db_prefix, "reserve_bytes") == 0)
    {
        get_reserve_bytes_database(reserve_bytes_index, 0);
        result = calc_multi_hash(client, db_prefix, reserve_bytes_index, hash);
    }
    else if (strcmp(db_prefix, "reserve_proofs") == 0)
    {
        result = calc_multi_hash(client, db_prefix, TOTAL_RESERVE_PROOFS_DATABASES, hash);
    }
    else
    {
        result = get_hash(client, db_prefix, hash);
    }

    return result;
}
