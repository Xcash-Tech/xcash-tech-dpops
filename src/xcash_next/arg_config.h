#ifndef ARG_CONFIG_H
#define ARG_CONFIG_H

#include <stdbool.h>


typedef struct {
    char *block_verifiers_secret_key;
    char *delegates_ip_address;
    char *xcash_daemon_ip_address;
    char *xcash_wallet_ip_address;
    int xcash_wallet_port;
    char *mongodb_uri;
    char *database_name;
    char *shared_delegates_database_name;
    bool delegates_website;
    bool shared_delegates_website;
    float fee;
    unsigned long long minimum_amount;
    int voter_inactivity_count;
    char * private_group;
    bool generate_key;
    bool debug_mode;
    bool debug_delegates_error;
    char *log_file_name;
    char *log_file_name_color;
    bool sync_dbs_from_node;
    char* sync_dbs_from_delegate_ip;
    int total_threads;
    char* server_log_file;
} arg_config_t;

// Define an enum for option IDs
typedef enum {
    OPTION_DELEGATES_IP_ADDRESS = 1000,
    OPTION_XCASH_DAEMON_IP_ADDRESS,
    OPTION_XCASH_WALLET_IP_ADDRESS,
    OPTION_XCASH_WALLET_PORT,
    OPTION_MONGODB_URI,
    OPTION_DATABASE_NAME,
    OPTION_SHARED_DELEGATES_DATABASE_NAME,
    OPTION_DELEGATES_WEBSITE,
    OPTION_SHARED_DELEGATES_WEBSITE,
    OPTION_FEE,
    OPTION_MINIMUM_AMOUNT,
    OPTION_VOTER_INACTIVITY_COUNT,
    OPTION_PRIVATE_GROUP,
    OPTION_GENERATE_KEY,
    OPTION_DEBUG,
    OPTION_DEBUG_DELEGATES_ERROR,
    OPTION_LOG_FILE,
    OPTION_LOG_FILE_COLOR,
    OPTION_SYNCHRONIZE_DATABASE_FROM_NETWORK_DATA_NODE,
    OPTION_SYNCHRONIZE_DATABASE_FROM_SPECIFIC_DELEGATE,
    OPTION_TOTAL_THREADS,
    OPTION_SERVER_LOG_FILE,
} option_ids;


#endif // ARG_CONFIG_H
