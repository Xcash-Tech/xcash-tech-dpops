#include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <time.h> 
#include <pthread.h>
// #include <netdb.h>
// #include <sys/sysinfo.h>
// #include <sys/resource.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>

// #include "define_macro_functions.h"
#include "define_macros.h"
// #include "define_macros_test.h"
#include "structures.h"
#include "variables.h"

// #include "shared_delegate_website_thread_server_functions.h"

// #include "block_verifiers_synchronize_functions.h"
// #include "block_verifiers_synchronize_check_functions.h"
// #include "block_verifiers_thread_server_functions.h"
// #include "block_verifiers_update_functions.h"
// #include "block_verifiers_functions.h"
// #include "database_functions.h"
// #include "count_database_functions.h"
// #include "insert_database_functions.h"
// #include "read_database_functions.h"
// #include "delete_database_functions.h"
// #include "network_daemon_functions.h"
// #include "network_functions.h"
// #include "network_security_functions.h"
// #include "network_wallet_functions.h"
// #include "server_functions.h"
// #include "string_functions.h"
// #include "VRF_functions.h"

// #include "xcash_db_helpers.h"
/*
-----------------------------------------------------------------------------------------------------------
Global Variables
-----------------------------------------------------------------------------------------------------------
*/


mongoc_client_pool_t* database_client_thread_pool;

// xcash-next
bool is_seed_node = false;
bool network_recovery_state;
bool is_shutdown_state = false;
int threads_running = 0;
FILE* server_log_fp =  NULL;
int sig_requests = 0;
bool is_block_creation_stage = false;

delegates_t delegates_all[BLOCK_VERIFIERS_TOTAL_AMOUNT];

// network data nodes
int network_data_node_settings; // 1 if a network data node, 0 if not a network data node 
char xcash_wallet_public_address[XCASH_WALLET_LENGTH+1]; // Holds your wallets public address
unsigned char secret_key_data[crypto_vrf_SECRETKEYBYTES+1]; // Holds the secret key for signing block verifier messages
char secret_key[VRF_SECRET_KEY_LENGTH+1]; // Holds the secret key text for signing block verifier messages
block_verifiers_list_t previous_block_verifiers_list; // The list of block verifiers name, public address and IP address for the previous round
block_verifiers_list_t current_block_verifiers_list; // The list of block verifiers name, public address and IP address for the current round
block_verifiers_list_t next_block_verifiers_list; // The list of block verifiers name, public address and IP address for the next round
struct synced_block_verifiers synced_block_verifiers; // The list of block verifiers for syncing the databases
struct main_nodes_list main_nodes_list; // The list of main nodes public address and IP address
struct network_data_nodes_list network_data_nodes_list; // The network data nodes
struct current_round_part_vote_data current_round_part_vote_data; // The vote data for the current part of the round
struct current_block_verifiers_majority_vote current_block_verifiers_majority_vote; // The vote majority data for the current part of the round
struct VRF_data VRF_data; // The list of all of the VRF data to send to the block producer.
struct blockchain_data blockchain_data; // The data for a new block to be added to the network.
struct error_message error_message; // holds all of the error messages and the functions for an error.
struct invalid_reserve_proofs invalid_reserve_proofs; // The invalid reserve proofs that the block verifier finds every round
struct network_data_nodes_sync_database_list network_data_nodes_sync_database_list; // Holds the network data nodes data and database hash for syncing network data nodes
struct block_verifiers_sync_database_list block_verifiers_sync_database_list; // Holds the block verifiers data and database hash for syncing the block verifiers
// struct delegates_online_status delegates_online_status[MAXIMUM_AMOUNT_OF_DELEGATES]; // Holds the delegates online status
struct block_height_start_time block_height_start_time; // Holds the block height start time data
struct private_group private_group; // Holds the private group data
char current_round_part[2]; // The current round part (1-4)
char current_round_part_backup_node[2]; // The current main node in the current round part (0-5)
pthread_rwlock_t rwlock;
pthread_rwlock_t rwlock_reserve_proofs;
pthread_mutex_t lock;
pthread_mutex_t database_lock;
pthread_mutex_t verify_network_block_lock;
pthread_mutex_t vote_lock;
pthread_mutex_t add_reserve_proof_lock;
pthread_mutex_t invalid_reserve_proof_lock;
pthread_mutex_t database_data_IP_address_lock;
pthread_mutex_t update_current_block_height_lock;
pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_t server_threads[100];
int epoll_fd;
int server_socket;

char current_block_height[BUFFER_SIZE_NETWORK_BLOCK_DATA]; // The current block height
char previous_block_hash[BLOCK_HASH_LENGTH+1]; // The current block height
int error_message_count; // The error message count
int main_network_data_node_create_block; // 1 if the main network data node can create a block, 0 if not
int main_network_data_node_receive_block; // 1 if you have received the block from the main network data node, 0 if not
int network_data_node_valid_amount; // The amount of network data nodes that were valid
int log_file_settings; // 0 to use the terminal, 1 to use a log file, 2 to use a log file with color output
char log_file[BUFFER_SIZE_NETWORK_BLOCK_DATA]; // The log file
char XCASH_DPOPS_delegates_IP_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH]; // The  block verifiers IP address to run the server on


char XCASH_daemon_IP_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH]; // The  block verifiers IP address to run the server on
// TODO remove this grobal variable
char MongoDB_uri[256]; // MongoDB uri

char XCASH_wallet_IP_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH]; // The  wallet IP address

int xcash_wallet_port; // The xcash wallet port
char database_name[BUFFER_SIZE_NETWORK_BLOCK_DATA];
char shared_delegates_database_name[BUFFER_SIZE_NETWORK_BLOCK_DATA];
char database_path_write[1024]; // holds the database write path
char database_path_write_before_majority[1024]; // holds the database write path before the majority sync
char database_path_read[1024]; // holds the database read path
int network_functions_test_settings;
int network_functions_test_error_settings; // 1 to display errors, 0 to not display errors when running the reset variables allocated on the heap test
int network_functions_test_server_messages_settings; // 1 to display server messages, 0 to not display server messages when running the test
int test_settings; // 1 when the test are running, 0 if not
int debug_settings; // 1 to show all incoming and outgoing message from the server
int registration_settings; // 1 when the registration mode is running, 0 when it is not
int synced_network_data_nodes[BLOCK_VERIFIERS_AMOUNT]; // the synced network data nodes
int synced_block_verifiers_nodes[DATABASE_TOTAL][BLOCK_VERIFIERS_AMOUNT]; // the synced block verifiers nodes
size_t block_verifiers_current_block_height[BLOCK_VERIFIERS_AMOUNT]; // holds the block verifiers current block heights
int production_settings; // 0 for production, 1 for test
int production_settings_database_data_settings; // The initialize the database settings
char website_path[1024]; // holds the path to the website if running a delegates explorer or shared delegates pool
int sync_previous_current_next_block_verifiers_settings; // sync the previous, current and next block verifiers if you had to restart
int database_data_socket_settings; // 1 to allow database data up to 50MB to be received in the server, 0 to only allow message up to BUFFER_SIZE
char* server_limit_IP_address_list; // holds all of the IP addresses that are currently running on the server. This can hold up to 1 million IP addresses
char* server_limit_public_address_list; // holds all of the public addresses that are currently running on the server. This can hold up to 1 million public addresses
int invalid_block_verifiers_count; // counts how many times your node did not receive the block from the main network backup node, to indicate if your node is not syncing
int backup_network_data_node_settings; // The network data node that will attempt to create the block if the block producer and backup block producer fail
int replayed_round_settings; // 1 if the round is a replayed round, 0 if not
char delegates_error_list[(MAXIMUM_BUFFER_SIZE_DELEGATES_NAME * 100) + 5000]; // Holds the list of delegates that did not complete a part of the round
int delegates_error_list_settings; // 1 if showing the delegates that error, 0 if not

int delegates_website; // 1 if the running the delegates websites, 0 if not
int shared_delegates_website; // 1 if the running the shared delegates websites, 0 if not
int total_threads; // The total threads
double fee; // the fee
long long int minimum_amount; // the minimum amount to send a payment
char voter_inactivity_count[10]; // the number of days to wait to remove an inactive delegates information from the database
