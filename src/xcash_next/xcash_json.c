#include <stdlib.h>
// #include <jansson.h>

#include "xcash_json.h"
#include "define_macros.h"

bool get_from_json(const char* json_string, const char* key_name, char** value_result) {
    bool result = false;

    // json_error_t error;
    // json_t *root, *key_object;

    // * value_result =  NULL;

    // // Parse the JSON string
    // root = json_loads(json_string, 0, &error);
    // // root = json_loads(json_string, JSON_DISABLE_EOF_CHECK, &error);
    // if (!root) {
    //     ERROR_PRINT("Error parsing JSON: %s", error.text);
    //     return false;
    // }

    return false;
    // json_t *third_element = json_array_get(root, 2);

    // DEBUG_PRINT("%s",json_dumps(third_element, 0));


    // // Extract the key_name field
    // key_object = json_object_get(root, key_name);
    //  if (!key_object) {
    //     ERROR_PRINT("JSON key '%s' not found", key_name);
    //     // TODO decref and cleanup
    //     json_decref(root);
    //     return false;
    //  }

    // // TODO decref and cleanup

    // DEBUG_PRINT("%s", json_string_value(key_object));


    return result;
}
