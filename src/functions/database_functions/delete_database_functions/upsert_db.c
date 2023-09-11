#include <mongoc/mongoc.h>
#include <bson/bson.h>
#include <stdio.h>
#include <stdlib.h>

#include "variables.h"
#include "cached_hashes.h"

#define ID_MAX_SIZE 256 //VRF_PUBLIC_KEY_LENGTH + 64*'0' + \0 + align just in case


bson_t *bson_copy_add_id(const bson_t *src, char *id_value)
{
    bson_iter_t iter;
    bson_t *dest = bson_new();
    const char *public_key_value = NULL;

    if (!bson_iter_init(&iter, src))
    {
        bson_destroy(dest);
        return NULL;
    }

    while (bson_iter_next(&iter))
    {
        const char *current_key = bson_iter_key(&iter);

        if (strcmp(current_key, "public_key") == 0)
        {
            public_key_value = bson_iter_utf8(&iter, NULL);
        }
        bson_append_value(dest, current_key, -1, bson_iter_value(&iter));
    }
    if (public_key_value) {
        snprintf(id_value, ID_MAX_SIZE, "0000000000000000000000000000000000000000000000000000000000000000%s", public_key_value);
        bson_append_utf8(dest, "_id", -1, id_value, -1);
    }
    return dest;
}


// that's stupid. in every system it's vice versa
// return 0 if error
// return 1 if ok
int upsert_data_to_db( const char *db_name, const char *collection_name, const char *db_data_source){
    mongoc_collection_t *collection;
    bson_t *docs = NULL;
    bson_error_t error;
    int result = 1;
    mongoc_client_t *client = NULL;
    char *db_data = NULL;


    size_t db_data_size = strlen(db_data_source)+3; // '[' +db_data_size +']' + \0
    db_data = malloc(db_data_size); 

    if (!db_data){
        fprintf(stderr, "%s:%d: Can't allocate memory for collection \"%s\": %s\n",  __func__,__LINE__, collection_name, error.message);
        return 0;
    }
    // make it standard json array
    snprintf(db_data,db_data_size,"[%s]",db_data_source);


    // get a temporary connection
    if (!(client = mongoc_client_pool_pop(database_client_thread_pool)))
    {
        fprintf(stderr, "%s:%d: Can't get client for connection \"%s\": %s\n",  __func__,__LINE__, collection_name, error.message);

        free(db_data);
        return 0;
    }

    // we need to rehash this db next time
    del_hash(client, collection_name);


    collection = mongoc_client_get_collection(client, db_name, collection_name);

    docs = bson_new_from_json((const uint8_t *)db_data, -1, &error);
    if (!docs){
        fprintf(stderr, "%s:%d: Parsing json error for collection \"%s\": %s\n",  __func__,__LINE__, collection_name, error.message);
        
        result = 0;
    }


    char id_value[ID_MAX_SIZE];  // VRF_PUBLIC_KEY_LENGTH + 64*'0' + \0 + align just in case
    bson_iter_t iter;
    if ((result == 1) & bson_iter_init(&iter, docs))
    {
        bson_t *opts;
        opts = BCON_NEW("upsert", BCON_BOOL(true));
        while ((result == 1) & bson_iter_next(&iter))
        {
            const uint8_t *data;
            uint32_t len;
            bson_t *doc_with_id;

            bson_iter_document(&iter, &len, &data);
            bson_t *current_doc = bson_new_from_data(data, len);

            // Create a copy of the document without the "_id" field
            doc_with_id = bson_copy_add_id(current_doc, id_value);

            // // Create a filter based on the extracted "_id"
            bson_t *filter = BCON_NEW("_id", BCON_UTF8(id_value));
            bson_t *update = BCON_NEW("$set", BCON_DOCUMENT(doc_with_id));

            // // Perform the update operation
            if (!mongoc_collection_update_one(collection, filter, update, opts, NULL, &error))
            {
                fprintf(stderr, "%s:%d: Can't update collection \"%s\": %s\n",  __func__,__LINE__, collection_name, error.message);
                result = 0;
            }

            // Cleanup
            bson_destroy(filter);
            bson_destroy(update);
            bson_destroy(doc_with_id);
            bson_destroy(current_doc);
        }
        bson_destroy(opts);
        bson_destroy(docs);
    }

    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(database_client_thread_pool, client);
    free(db_data);



    return result;
}
