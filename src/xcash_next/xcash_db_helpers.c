#include "xcash_db_helpers.h"

#include <bson/bson.h>

#include "db_operations.h"

const char *collection_names[XCASH_DB_COUNT] = {"delegates", "statistics", "reserve_proofs", "reserve_bytes"};

bson_t *assign_ids(bson_t *docs, xcash_dbs_t collection_id) {
    const char *key_name = NULL;
    const char *key_name_fmt = NULL;
    char id_value[ID_MAX_SIZE];
    bson_iter_t iter;
    int index = 0;
    char str_index[16];  // for converting integer to string just placeholder for 16 digits index

    switch (collection_id) {
        case XCASH_DB_DELEGATES:
            key_name = "public_key";
            key_name_fmt = "0000000000000000000000000000000000000000000000000000000000000000%s";
            break;

        case XCASH_DB_STATISTICS:
            key_name = "__placeholder__";
            key_name_fmt =
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000";
            break;

        case XCASH_DB_RESERVE_PROOFS:
            key_name = "public_address_created_reserve_proof";
            key_name_fmt = "000000000000000000000000000000%s";
            break;

        case XCASH_DB_RESERVE_BYTES:
            key_name = "reserve_bytes_data_hash";
            key_name_fmt = "%s";
            break;

        default:
            break;
    };

    bson_t *new_docs = bson_new();

    if (bson_iter_init(&iter, docs)) {
        while (bson_iter_next(&iter)) {
            const uint8_t *data;
            uint32_t len;

            bson_iter_document(&iter, &len, &data);
            bson_t *sub_doc = bson_new_from_data(data, len);

            bson_iter_t sub_iter;
            if (bson_iter_init_find(&sub_iter, sub_doc, key_name)) {
                const char *key_value = bson_iter_utf8(&sub_iter, NULL);
                snprintf(id_value, sizeof(id_value), key_name_fmt, key_value);

                bson_append_utf8(sub_doc, "_id", -1, id_value, -1);
            } else {
                if (collection_id == XCASH_DB_STATISTICS) {
                    bson_append_utf8(sub_doc, "_id", -1, key_name_fmt, -1);
                }
            }
            snprintf(str_index, sizeof(str_index), "%d", index);
            bson_append_document(new_docs, str_index, -1, sub_doc);
            bson_destroy(sub_doc);
        }
    }

    return new_docs;
}

int upsert_json_to_db(const char *db_name, const xcash_dbs_t collection_id, int db_file_index,
                      const char *db_data_source, bool is_json_array) {
    bson_t *docs = NULL;
    bson_error_t error;
    char *db_data = NULL;
    bson_t *updated_docs = NULL;

    char collection_name[DB_COLLECTION_NAME_SIZE];

    switch (collection_id) {
        case XCASH_DB_DELEGATES:
        case XCASH_DB_STATISTICS:
            sprintf(collection_name, "%s", collection_names[collection_id]);
            break;
        case XCASH_DB_RESERVE_PROOFS:
        case XCASH_DB_RESERVE_BYTES:
            sprintf(collection_name, "%s_%d", collection_names[collection_id], db_file_index);
            break;
        default:
            break;
    }

    size_t db_data_size = strlen(db_data_source) + 3;  // '[' +db_data_size +']' + \0
    db_data = malloc(db_data_size);

    if (!db_data) {
        DEBUG_PRINT("Can't allocate memory for collection '%s'\n", collection_name);
        return XCASH_ERROR;
    }
    // make it standard json array
    const char *conversion_parameter;
    if (!is_json_array)
        conversion_parameter = "[%s]";
    else
        conversion_parameter = "%s";

    snprintf(db_data, db_data_size, conversion_parameter, db_data_source);

    docs = bson_new_from_json((const uint8_t *)db_data, -1, &error);
    if (!docs) {
        DEBUG_PRINT("Parsing json error for collection \"%s\": %s\n", collection_name, error.message);
        free(db_data);
        return XCASH_ERROR;
    }

    updated_docs = assign_ids(docs, collection_id);

    bool result = db_upsert_multi_docs(db_name, collection_name, updated_docs, &error);
    if (!result) {
        DEBUG_PRINT("Failed to upsert document array \"%s\": %s", collection_name, error.message);
        bson_destroy(docs);
        bson_destroy(updated_docs);
        free(db_data);
        return XCASH_ERROR;
    }

    // Cleanup
    bson_destroy(docs);
    bson_destroy(updated_docs);
    free(db_data);

    return XCASH_OK;
}

int count_db_delegates(void) {
    bson_error_t error;
    bool result = false;
    int64_t count;

    result = db_count_doc(DPOPS_DB, collection_names[XCASH_DB_DELEGATES], &count, &error);
    if (!result) {
        count = -1;
    }
    return count;
}

int count_db_statistics(void) {
    bson_error_t error;
    bool result = false;
    int64_t count;

    result = db_count_doc(DPOPS_DB, collection_names[XCASH_DB_STATISTICS], &count, &error);
    if (!result) {
        count = -1;
    }
    return count;
}

int count_db_reserve_proofs(void) {
    bson_error_t error;
    bool result = false;
    int64_t count;

    result = db_count_doc(DPOPS_DB, collection_names[XCASH_DB_RESERVE_PROOFS], &count, &error);
    if (!result) {
        count = -1;
    }
    return count;
}

int count_db_reserve_bytes(void) {
    bson_error_t error;
    bool result = false;
    int64_t count;

    result = db_count_doc(DPOPS_DB, collection_names[XCASH_DB_RESERVE_BYTES], &count, &error);
    if (!result) {
        count = -1;
    }
    return count;
}

int count_recs(const bson_t *recs) {
    bson_iter_t iter;
    int count = 0;

    if (bson_iter_init(&iter, recs)) {
        while (bson_iter_next(&iter)) {
            count++;
        }
    }
    return count;
}
