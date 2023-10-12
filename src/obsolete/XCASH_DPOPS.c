#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <pthread.h>
#include <netdb.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>

#include "define_macro_functions.h"
#include "define_macros.h"
#include "define_macros_test.h"
#include "structures.h"
#include "variables.h"

#include "shared_delegate_website_thread_server_functions.h"

#include "block_verifiers_synchronize_functions.h"
#include "block_verifiers_synchronize_check_functions.h"
#include "block_verifiers_thread_server_functions.h"
#include "block_verifiers_update_functions.h"
#include "block_verifiers_functions.h"
#include "database_functions.h"
#include "count_database_functions.h"
#include "insert_database_functions.h"
#include "read_database_functions.h"
#include "delete_database_functions.h"
#include "network_daemon_functions.h"
#include "network_functions.h"
#include "network_security_functions.h"
#include "network_wallet_functions.h"
#include "server_functions.h"
#include "string_functions.h"
#include "VRF_functions.h"

#include "XCASH_DPOPS_test.h"
#include "XCASH_DPOPS.h"

#include "xcash_db_helpers.h"

#include "test_related.h"


#include "xcash_db.h"
/*
-----------------------------------------------------------------------------------------------------------
Name: initialize_data
Description: Initializes the global variables
Parameters:
  parameters_count - The parameter count
  parameters - The parameters
-----------------------------------------------------------------------------------------------------------
*/

void initialize_data(int parameters_count, char* parameters[])
{
  // Variables
  char data[SMALL_BUFFER_SIZE];
  size_t count = 0;
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;

  // define macros
  #define INITIALIZE_DATA_ERROR \
  memcpy(error_message.function[error_message.total],"initialize_data",15); \
  memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48); \
  error_message.total++; \
  print_error_message(current_date_and_time,current_UTC_date_and_time,data); \
  exit(0);

  memset(data,0,sizeof(data));

  // initialize the global variables
  memset(current_block_height,0,sizeof(current_block_height));
  memset(current_round_part,0,sizeof(current_round_part));
  memset(current_round_part_backup_node,0,sizeof(current_round_part_backup_node));
  memset(secret_key,0,sizeof(secret_key));
  memset(secret_key_data,0,sizeof(secret_key_data));
  memset(log_file,0,sizeof(log_file));
  memset(XCASH_DPOPS_delegates_IP_address,0,sizeof(XCASH_DPOPS_delegates_IP_address));
  memcpy(XCASH_DPOPS_delegates_IP_address,"127.0.0.1",9);

  memset(XCASH_daemon_IP_address,0,sizeof(XCASH_daemon_IP_address));
  memcpy(XCASH_daemon_IP_address,"127.0.0.1",9);

  memset(MongoDB_IP_address,0,sizeof(MongoDB_IP_address));
  memcpy(MongoDB_IP_address,"127.0.0.1",9);

  memset(database_name,0,sizeof(database_name));
  memset(shared_delegates_database_name,0,sizeof(shared_delegates_database_name));
  memset(database_path_write,0,sizeof(database_path_write));
  memset(database_path_write_before_majority,0,sizeof(database_path_write_before_majority));
  memset(database_path_read,0,sizeof(database_path_read));
  memset(voter_inactivity_count,0,sizeof(voter_inactivity_count));
  log_file_settings = 0;

  sprintf(XCASH_wallet_IP_address,"127.0.0.1");
  xcash_wallet_port = XCASH_WALLET_PORT;

  network_functions_test_settings = 0;
  network_functions_test_error_settings = 1;
  network_functions_test_server_messages_settings = 1;
  debug_settings = 0;
  registration_settings = 0;
  block_height_start_time.block_height_start_time = 0;
  production_settings = 1;
  production_settings_database_data_settings = 0;
  sync_previous_current_next_block_verifiers_settings = 1;
  database_data_socket_settings = 0;
  invalid_block_verifiers_count = 0;
  replayed_round_settings = 0;
  delegates_error_list_settings = 0;

  pthread_rwlock_init(&rwlock,NULL);
  pthread_rwlock_init(&rwlock_reserve_proofs,NULL);
  pthread_mutex_init(&lock, NULL);
  pthread_mutex_init(&database_lock, NULL);
  pthread_mutex_init(&verify_network_block_lock, NULL);
  pthread_mutex_init(&vote_lock, NULL);
  pthread_mutex_init(&add_reserve_proof_lock, NULL);
  pthread_mutex_init(&invalid_reserve_proof_lock, NULL);
  pthread_mutex_init(&database_data_IP_address_lock, NULL);
  pthread_mutex_init(&update_current_block_height_lock, NULL);

  server_limit_IP_address_list = (char*)calloc(15728640,sizeof(char)); // 15 MB
  server_limit_public_address_list = (char*)calloc(15728640,sizeof(char)); // 15 MB
   
  // check if the memory needed was allocated on the heap successfully
  if (server_limit_IP_address_list == NULL || server_limit_public_address_list == NULL)
  {
    INITIALIZE_DATA_ERROR;
  }

  // initialize the error_message struct
  for (count = 0; count < TOTAL_ERROR_MESSAGES; count++)
  {
    error_message.function[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    error_message.data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));

    if (error_message.function[count] == NULL || error_message.data[count] == NULL)
    {
      exit(0);
    }
  }
  error_message.total = 0;

  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    // initialize the previous, current and next block_verifiers_list struct 
    memset(previous_block_verifiers_list.block_verifiers_name[count],0,sizeof(previous_block_verifiers_list.block_verifiers_name[count]));
    memset(previous_block_verifiers_list.block_verifiers_public_address[count],0,sizeof(previous_block_verifiers_list.block_verifiers_public_address[count]));
    memset(previous_block_verifiers_list.block_verifiers_public_key[count],0,sizeof(previous_block_verifiers_list.block_verifiers_public_key[count]));
    memset(previous_block_verifiers_list.block_verifiers_IP_address[count],0,sizeof(previous_block_verifiers_list.block_verifiers_IP_address[count]));

    memset(current_block_verifiers_list.block_verifiers_name[count],0,sizeof(current_block_verifiers_list.block_verifiers_name[count]));
    memset(current_block_verifiers_list.block_verifiers_public_address[count],0,sizeof(current_block_verifiers_list.block_verifiers_public_address[count]));
    memset(current_block_verifiers_list.block_verifiers_public_key[count],0,sizeof(current_block_verifiers_list.block_verifiers_public_key[count]));
    memset(current_block_verifiers_list.block_verifiers_IP_address[count],0,sizeof(current_block_verifiers_list.block_verifiers_IP_address[count]));

    memset(next_block_verifiers_list.block_verifiers_name[count],0,sizeof(next_block_verifiers_list.block_verifiers_name[count]));
    memset(next_block_verifiers_list.block_verifiers_public_address[count],0,sizeof(next_block_verifiers_list.block_verifiers_public_address[count]));
    memset(next_block_verifiers_list.block_verifiers_public_key[count],0,sizeof(next_block_verifiers_list.block_verifiers_public_key[count]));
    memset(next_block_verifiers_list.block_verifiers_IP_address[count],0,sizeof(next_block_verifiers_list.block_verifiers_IP_address[count]));

    // initialize the synced_block_verifiers struct 
    memset(synced_block_verifiers.synced_block_verifiers_public_address[count],0,sizeof(synced_block_verifiers.synced_block_verifiers_public_address[count]));
    memset(synced_block_verifiers.synced_block_verifiers_public_key[count],0,sizeof(synced_block_verifiers.synced_block_verifiers_public_key[count]));
    memset(synced_block_verifiers.synced_block_verifiers_IP_address[count],0,sizeof(synced_block_verifiers.synced_block_verifiers_IP_address[count]));
    memset(synced_block_verifiers.vote_settings[count],0,sizeof(synced_block_verifiers.vote_settings[count]));
  }
  synced_block_verifiers.vote_settings_true = 0;
  synced_block_verifiers.vote_settings_false = 0;
  synced_block_verifiers.last_refresh_time_of_synced_block_verifiers = 0;

  // initialize the main_nodes_list struct 
  memset(main_nodes_list.block_producer_public_address,0,sizeof(main_nodes_list.block_producer_public_address));
  memset(main_nodes_list.block_producer_IP_address,0,sizeof(main_nodes_list.block_producer_IP_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_1_public_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_1_public_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_1_IP_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_1_IP_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_2_public_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_2_public_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_2_IP_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_2_IP_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_3_public_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_3_public_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_3_IP_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_3_IP_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_4_public_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_4_public_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_4_IP_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_4_IP_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_5_public_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_5_public_address));
  memset(main_nodes_list.block_producer_backup_block_verifier_5_IP_address,0,sizeof(main_nodes_list.block_producer_backup_block_verifier_5_IP_address));

  // initialize the network_data_nodes_list struct
  for (count = 0; count < NETWORK_DATA_NODES_AMOUNT; count++)
  {
    memset(network_data_nodes_list.network_data_nodes_public_address[count],0,sizeof(network_data_nodes_list.network_data_nodes_public_address[count]));
    memset(network_data_nodes_list.network_data_nodes_IP_address[count],0,sizeof(network_data_nodes_list.network_data_nodes_IP_address[count]));
    network_data_nodes_list.online_status[count] = 1;
  }

  // set the network_data_node_settings
  network_data_node_settings = 0;

  // initialize the current_round_part_vote_data struct
  memset(current_round_part_vote_data.current_vote_results,0,sizeof(current_round_part_vote_data.current_vote_results));

  // initialize the VRF_data struct 
  VRF_data.vrf_secret_key_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  VRF_data.vrf_secret_key = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
  VRF_data.vrf_public_key_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  VRF_data.vrf_public_key = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
  VRF_data.vrf_alpha_string_data = (char*)calloc(BUFFER_SIZE,sizeof(char));
  VRF_data.vrf_alpha_string = (unsigned char*)calloc(BUFFER_SIZE,sizeof(unsigned char));
  VRF_data.vrf_proof_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  VRF_data.vrf_proof = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
  VRF_data.vrf_beta_string_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  VRF_data.vrf_beta_string = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
  VRF_data.block_blob = (char*)calloc(BUFFER_SIZE,sizeof(char));
  VRF_data.reserve_bytes_data_hash = (char*)calloc(DATA_HASH_LENGTH+1,sizeof(char));

  // check if the memory needed was allocated on the heap successfully
  if (VRF_data.vrf_public_key_data == NULL || VRF_data.vrf_public_key == NULL || VRF_data.vrf_alpha_string_data == NULL || VRF_data.vrf_alpha_string == NULL || VRF_data.vrf_proof_data == NULL || VRF_data.vrf_proof == NULL || VRF_data.vrf_beta_string_data == NULL || VRF_data.vrf_beta_string == NULL || VRF_data.block_blob == NULL)
  {
    INITIALIZE_DATA_ERROR;
  }

  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    VRF_data.block_verifiers_vrf_secret_key_data[count] = (char*)calloc(VRF_SECRET_KEY_LENGTH+1,sizeof(char));
    VRF_data.block_verifiers_vrf_secret_key[count] = (unsigned char*)calloc(crypto_vrf_SECRETKEYBYTES+1,sizeof(unsigned char));
    VRF_data.block_verifiers_vrf_public_key_data[count] = (char*)calloc(VRF_PUBLIC_KEY_LENGTH+1,sizeof(char));
    VRF_data.block_verifiers_vrf_public_key[count] = (unsigned char*)calloc(crypto_vrf_PUBLICKEYBYTES+1,sizeof(unsigned char));
    VRF_data.block_verifiers_random_data[count] = (char*)calloc(RANDOM_STRING_LENGTH+1,sizeof(char));
    VRF_data.block_blob_signature[count] = (char*)calloc(VRF_PROOF_LENGTH+VRF_BETA_LENGTH+1,sizeof(char));
   
    // check if the memory needed was allocated on the heap successfully
    if (VRF_data.block_blob_signature[count] == NULL || VRF_data.block_verifiers_random_data[count] == NULL)
    {
      INITIALIZE_DATA_ERROR;
    }
  }

  // initialize the blockchain_data struct 
  blockchain_data.network_version_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.timestamp_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.previous_block_hash_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.nonce_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_reward_transaction_version_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.unlock_block_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_reward_input_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.vin_type_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_height_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_reward_output_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.block_reward_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.stealth_address_output_tag_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.stealth_address_output_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.extra_bytes_size_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.transaction_public_key_tag_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.transaction_public_key_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.extra_nonce_tag_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.reserve_bytes_size_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_public_address = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));  
  blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_secret_key = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
  blockchain_data.blockchain_reserve_bytes.vrf_public_key_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_public_key = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
  blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data = (char*)calloc(BUFFER_SIZE,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_alpha_string = (unsigned char*)calloc(BUFFER_SIZE,sizeof(unsigned char));
  blockchain_data.blockchain_reserve_bytes.vrf_proof_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_proof = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
  blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_beta_string = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
  blockchain_data.blockchain_reserve_bytes.vrf_data_round = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.vrf_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.blockchain_reserve_bytes.previous_block_hash_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));

  // check if the memory needed was allocated on the heap successfully
  if (blockchain_data.network_version_data == NULL || blockchain_data.timestamp_data == NULL || blockchain_data.previous_block_hash_data == NULL || blockchain_data.nonce_data == NULL || blockchain_data.block_reward_transaction_version_data == NULL || blockchain_data.unlock_block_data == NULL || blockchain_data.block_reward_input_data == NULL || blockchain_data.vin_type_data == NULL || blockchain_data.block_height_data == NULL || blockchain_data.block_reward_output_data == NULL || blockchain_data.block_reward_data == NULL || blockchain_data.stealth_address_output_tag_data == NULL || blockchain_data.stealth_address_output_data == NULL || blockchain_data.extra_bytes_size_data == NULL || blockchain_data.transaction_public_key_tag_data == NULL || blockchain_data.transaction_public_key_data == NULL || blockchain_data.extra_nonce_tag_data == NULL || blockchain_data.reserve_bytes_size_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_public_address == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data == NULL || blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names == NULL || blockchain_data.blockchain_reserve_bytes.vrf_public_key_data == NULL || blockchain_data.blockchain_reserve_bytes.vrf_public_key == NULL || blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data == NULL || blockchain_data.blockchain_reserve_bytes.vrf_alpha_string == NULL || blockchain_data.blockchain_reserve_bytes.vrf_proof_data == NULL || blockchain_data.blockchain_reserve_bytes.vrf_proof == NULL || blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data == NULL || blockchain_data.blockchain_reserve_bytes.vrf_beta_string == NULL || blockchain_data.blockchain_reserve_bytes.vrf_data_round == NULL || blockchain_data.blockchain_reserve_bytes.vrf_data == NULL || blockchain_data.blockchain_reserve_bytes.previous_block_hash_data == NULL)
  {
    INITIALIZE_DATA_ERROR;
  }
  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count] = (char*)calloc(1000,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count] = (char*)calloc(1000,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count] = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count] = (unsigned char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(unsigned char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));

    // check if the memory needed was allocated on the heap successfully
    if (blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count] == NULL || blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count] == NULL || blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count] == NULL)
    {
      INITIALIZE_DATA_ERROR;
    }
  }
  blockchain_data.ringct_version_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.transaction_amount_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++)
  {
    blockchain_data.transactions[count] = (char*)calloc(TRANSACTION_HASH_LENGTH+1,sizeof(char));

    // check if the memory needed was allocated on the heap successfully
    if (blockchain_data.transactions[count] == NULL)
    {
      INITIALIZE_DATA_ERROR;
    }
  }
  invalid_reserve_proofs.count = 0;

  for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++)
  {
    blockchain_data.transactions[count] = (char*)calloc(TRANSACTION_HASH_LENGTH+1,sizeof(char));

    // check if the memory needed was allocated on the heap successfully
    if (blockchain_data.transactions[count] == NULL)
    {
      INITIALIZE_DATA_ERROR;
    }
  }

  // set the production settings
  for (count = 0; count < (size_t)parameters_count; count++)
  { 
    if (strncmp(parameters[count],"--test-mode",BUFFER_SIZE) == 0)
    {
      production_settings = 0;
      sscanf(parameters[count+1], "%d", &production_settings_database_data_settings);
    }
  }

  // initialize the private group
  private_group.private_group_settings = 0;

  // initialize the network data nodes
  INITIALIZE_NETWORK_DATA_NODES;
  return;

  #undef INITIALIZE_DATA_ERROR
}






/*
-----------------------------------------------------------------------------------------------------------
Name: create_overall_database_connection
Description: Create a database connection
-----------------------------------------------------------------------------------------------------------
*/

void create_overall_database_connection(void)
{
  // Variables
  char data[SMALL_BUFFER_SIZE];
  char mongo_uri[256];

  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;

  #define CREATE_OVERALL_DATABASE_CONNECTION_ERROR \
  memcpy(error_message.function[error_message.total],"create_overall_database_connection",34); \
  memcpy(error_message.data[error_message.total],"Could not create a connection for the database",46); \
  error_message.total++; \
  print_error_message(current_date_and_time,current_UTC_date_and_time,data); \
  mongoc_uri_destroy(uri_thread_pool); \
  mongoc_cleanup(); \
  exit(0);

  memset(data,0,sizeof(data));

  // initialize the database connection
  mongoc_init();

  // create a connection to the database
  sprintf(mongo_uri,"mongodb://%s:27017", MongoDB_IP_address);
  if (!(uri_thread_pool = mongoc_uri_new_with_error(mongo_uri, &error)))
  {
    CREATE_OVERALL_DATABASE_CONNECTION_ERROR;
  }

  if (!(database_client_thread_pool = mongoc_client_pool_new(uri_thread_pool)))
  {
    CREATE_OVERALL_DATABASE_CONNECTION_ERROR;
  }
  return;

  #undef CREATE_OVERALL_DATABASE_CONNECTION_ERROR
}





/*
-----------------------------------------------------------------------------------------------------------
Name: set_parameters
Description: Sets the parameters
Parameters:
  parameters_count - The parameter count
  parameters - The parameters
Return: 0 if an error has occured, 1 if successfull, 2 to disable the timers
-----------------------------------------------------------------------------------------------------------
*/

int set_parameters(int parameters_count, char* parameters[])
{
  // define macros
  #define MINIMUM_THREADS_AMOUNT 2

  #define database_reset \
  mongoc_client_pool_destroy(database_client_thread_pool); \
  mongoc_uri_destroy(uri_thread_pool); \
  mongoc_cleanup();

  #define SET_PARAMETERS_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"set_parameters",14); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  print_error_message(current_date_and_time,current_UTC_date_and_time,data); \
  database_reset; \
  exit(0);

  // Variables
  char data[SMALL_BUFFER_SIZE];
  char data2[SMALL_BUFFER_SIZE];
  size_t count;
  size_t count2 = 0;
  size_t count3;
  size_t counter;
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));

  // set the default parameter settings
  total_threads = get_nprocs();
  delegates_website = 0;
  shared_delegates_website = 0;
  log_file_settings = 0;
  memcpy(database_name,DATABASE_NAME,sizeof(DATABASE_NAME)-1);
  memcpy(shared_delegates_database_name,DATABASE_NAME_DELEGATES,sizeof(DATABASE_NAME_DELEGATES)-1);
  log_file_settings = 0;
  test_settings = 0;
  memcpy(voter_inactivity_count,VOTER_INACTIVITY_COUNT,sizeof(VOTER_INACTIVITY_COUNT)-1);
  xcash_wallet_port = XCASH_WALLET_PORT;

  // set the current_round_part, current_round_part_backup_node and server message, this way the node will start at the begining of a round
  memset(current_round_part,0,sizeof(current_round_part));
  memset(current_round_part_backup_node,0,sizeof(current_round_part_backup_node));
  memcpy(current_round_part,"1",sizeof(char));
  memcpy(current_round_part_backup_node,"0",sizeof(char));

  // check all of the parameters to see if there is a block verifier secret key
  if (parameters_count < 3)
  {
    SET_PARAMETERS_ERROR("Could not get the block verifiers secret key.\nMake sure to run xcash-dpops with the --block-verifiers-secret-key parameter");
  }
  
  // check the parameters
  for (count = 0, count2 = 0; count < (size_t)parameters_count; count++)
  { 
    if (strncmp(parameters[count],"--block-verifiers-secret-key",BUFFER_SIZE) == 0)
    {
      count2 = 1;
    }
  }

  if (count2 != 1)
  {
    SET_PARAMETERS_ERROR("Could not get the block verifiers secret key.\nMake sure to run xcash-dpops with the --block-verifiers-secret-key parameter");
  }

  // check the parameters
  for (count = 0; count < (size_t)parameters_count; count++)
  { 
    if (strncmp(parameters[count],"--block-verifiers-secret-key",BUFFER_SIZE) == 0)
    {
      if (strlen(parameters[count+1]) != VRF_SECRET_KEY_LENGTH)
      {
        SET_PARAMETERS_ERROR("Invalid block verifiers secret key");
      }

      // get the secret key for signing messages
      memcpy(secret_key,parameters[count+1],VRF_SECRET_KEY_LENGTH);
    
      // convert the hexadecimal string to a string
      for (count3 = 0, counter = 0; count3 < VRF_SECRET_KEY_LENGTH; counter++, count3 += 2)
      {
        memset(data2,0,sizeof(data2));
        memcpy(data2,&secret_key[count3],2);
        secret_key_data[counter] = (unsigned char)strtol(data2, NULL, 16);
      }
    }
    if (strncmp(parameters[count],"--test",BUFFER_SIZE) == 0)
    {
      get_node_data();
      test(0);
      database_reset;
      exit(0);
    }
    if (strncmp(parameters[count],"--quick-test",BUFFER_SIZE) == 0)
    {
      get_node_data();
      test(1);
      database_reset;
      exit(0);
    }
    if (strncmp(parameters[count],"--optimization-test",BUFFER_SIZE) == 0)
    {
      get_node_data();
      test(2);
      database_reset;
      exit(0);
    }
    if (strncmp(parameters[count],"--debug",BUFFER_SIZE) == 0)
    {
      debug_settings = 1;
    }
    if (strncmp(parameters[count],"--debug-delegates-error",BUFFER_SIZE) == 0)
    {
      delegates_error_list_settings = 1;
    }
    if (strncmp(parameters[count],"--delegates-ip-address",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      memset(XCASH_DPOPS_delegates_IP_address,0,strlen(XCASH_DPOPS_delegates_IP_address));
      memcpy(XCASH_DPOPS_delegates_IP_address,parameters[count+1],strnlen(parameters[count+1],sizeof(XCASH_DPOPS_delegates_IP_address)));
    }


    if (strncmp(parameters[count],"--xcash-daemon-ip-address",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      strncpy(XCASH_daemon_IP_address,parameters[count+1],sizeof(XCASH_daemon_IP_address)-1);
    }

    if (strncmp(parameters[count],"--xcash-wallet-ip-address",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      strncpy(XCASH_wallet_IP_address,parameters[count+1],sizeof(XCASH_wallet_IP_address)-1);
    }

    if (strncmp(parameters[count],"--xcash-wallet-port",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      sscanf(parameters[count+1],"%d",&xcash_wallet_port);
    }

    if (strncmp(parameters[count],"--database-name",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      memset(database_name,0,sizeof(database_name));
      memcpy(database_name,parameters[count+1],strnlen(parameters[count+1],sizeof(database_name)));
    }
    if (strncmp(parameters[count],"--shared-delegates-database-name",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      memset(shared_delegates_database_name,0,sizeof(shared_delegates_database_name));
      memcpy(shared_delegates_database_name,parameters[count+1],strnlen(parameters[count+1],sizeof(shared_delegates_database_name)));
    }
    if (strncmp(parameters[count],"--log-file",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      log_file_settings = 1;
      memcpy(log_file,parameters[count+1],strnlen(parameters[count+1],sizeof(log_file)));

      memset(data,0,sizeof(data));
      color_print("\n\n\n\n\nxcash-dpops - Version 1.0.0\n","green");
      memcpy(data,"Successfully received the public address:",41);
      memcpy(data+41,xcash_wallet_public_address,XCASH_WALLET_LENGTH);
      color_print(data,"green");
    }
    if (strncmp(parameters[count],"--log-file_color",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      log_file_settings = 2;
      memcpy(log_file,parameters[count+1],strnlen(parameters[count+1],sizeof(log_file)));

      memset(data,0,sizeof(data));
      color_print("\n\n\n\n\nxcash-dpops - Version 1.0.0\n","green");
      memcpy(data,"Successfully received the public address:",41);
      memcpy(data+41,xcash_wallet_public_address,XCASH_WALLET_LENGTH);
      color_print(data,"green");
    }
    if (strncmp(parameters[count],"--synchronize-database-from-network-data-node",BUFFER_SIZE) == 0)
    {
      get_node_data();
      color_print("Syncing the block verifiers list","yellow");
      sync_all_block_verifiers_list(1,1);
      color_print("Syncing the reserve bytes database","yellow");
      sync_reserve_bytes_database(2,0,"");
      color_print("Syncing the reserve proofs database","yellow");
      sync_reserve_proofs_database(2,"");
      color_print("Syncing the delegates database","yellow");
      sync_delegates_database(2,"");
      color_print("Syncing the statistics database","yellow");
      sync_statistics_database(2,"");
      color_print("Successfully synced all databases","yellow");
      database_reset;
      exit(0);
    }
    if (strncmp(parameters[count],"--synchronize-database-from-specific-delegate",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      get_node_data();
      color_print("Syncing the block verifiers list","yellow");
      sync_all_block_verifiers_list(1,1);
      color_print("Syncing the reserve bytes database","yellow");
      sync_reserve_bytes_database(0,0,parameters[count+1]);
      color_print("Syncing the reserve proofs database","yellow");
      sync_reserve_proofs_database(0,parameters[count+1]);
      color_print("Syncing the delegates database","yellow");
      sync_delegates_database(0,parameters[count+1]);
      color_print("Syncing the statistics database","yellow");
      sync_statistics_database(0,parameters[count+1]);
      color_print("Successfully synced all databases","yellow");
      database_reset;
      exit(0);
    }
    if (strncmp(parameters[count],"--disable-synchronizing-databases-and-starting-timers",BUFFER_SIZE) == 0)
    {
      return 2;
    }
    if (strncmp(parameters[count],"--registration-mode",BUFFER_SIZE) == 0)
    {
      registration_settings = 1;
      goto start_time;
      return 3;
    }
    if (strncmp(parameters[count],"--start-time",BUFFER_SIZE) == 0)
    {
      start_time:
      sscanf(parameters[count+1], "%d", &block_height_start_time.block_height_start_time_year);
      sscanf(parameters[count+2], "%d", &block_height_start_time.block_height_start_time_month);
      sscanf(parameters[count+3], "%d", &block_height_start_time.block_height_start_time_day);
      sscanf(parameters[count+4], "%d", &block_height_start_time.block_height_start_time_hour);
      sscanf(parameters[count+5], "%d", &block_height_start_time.block_height_start_time_minute);

      // if the program restarts dont wait for the start_time again
      get_current_UTC_time(current_date_and_time,current_UTC_date_and_time);
      if ((current_UTC_date_and_time.tm_year > block_height_start_time.block_height_start_time_year) || (current_UTC_date_and_time.tm_year == block_height_start_time.block_height_start_time_year && current_UTC_date_and_time.tm_mon > block_height_start_time.block_height_start_time_month) || (current_UTC_date_and_time.tm_year == block_height_start_time.block_height_start_time_year && current_UTC_date_and_time.tm_mon == block_height_start_time.block_height_start_time_month && current_UTC_date_and_time.tm_mday > block_height_start_time.block_height_start_time_day) || (current_UTC_date_and_time.tm_year == block_height_start_time.block_height_start_time_year && current_UTC_date_and_time.tm_mon == block_height_start_time.block_height_start_time_month && current_UTC_date_and_time.tm_mday == block_height_start_time.block_height_start_time_day && current_UTC_date_and_time.tm_hour > block_height_start_time.block_height_start_time_hour) || (current_UTC_date_and_time.tm_year == block_height_start_time.block_height_start_time_year && current_UTC_date_and_time.tm_mon == block_height_start_time.block_height_start_time_month && current_UTC_date_and_time.tm_mday == block_height_start_time.block_height_start_time_day && current_UTC_date_and_time.tm_hour == block_height_start_time.block_height_start_time_hour && current_UTC_date_and_time.tm_min > block_height_start_time.block_height_start_time_minute))
      {
        registration_settings = 0;
        block_height_start_time.block_height_start_time = 0;
      }
      else
      {
        block_height_start_time.block_height_start_time = 1;
      }
    }
    if (strncmp(parameters[count],"--delegates-website",BUFFER_SIZE) == 0)
    {
      delegates_website = 1;
    }
    if (strncmp(parameters[count],"--shared-delegates-website",BUFFER_SIZE) == 0)
    {
      shared_delegates_website = 1;
    }
    if (strncmp(parameters[count],"--private-group",BUFFER_SIZE) == 0)
    {
      memset(private_group.private_group_file,0,sizeof(private_group.private_group_file));
      memcpy(private_group.private_group_file,parameters[count+1],strlen(parameters[count+1]));
      private_group.private_group_settings = 1; 

      // load the private group configuration
      if (load_private_group_configuration() == 0)
      {
        color_print("The private group file could not be loaded","red");
        exit(0);
      } 
    }
    if (strncmp(parameters[count],"--fee",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      sscanf(parameters[count+1], "%lf", &fee);
    }
    if (strncmp(parameters[count],"--minimum-amount",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      sscanf(parameters[count+1], "%lld", &minimum_amount);
    }
    if (strncmp(parameters[count],"--voter-inactivity-count",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      memset(voter_inactivity_count,0,sizeof(voter_inactivity_count));
      memcpy(voter_inactivity_count,parameters[count+1],strnlen(parameters[count+1],sizeof(voter_inactivity_count)));
    }    
    if (strncmp(parameters[count],"--total-threads",BUFFER_SIZE) == 0 && count != (size_t)parameters_count)
    {
      if (total_threads >= MINIMUM_THREADS_AMOUNT)
      {
        sscanf(parameters[count+1], "%d", &total_threads);
      }
      else
      {
        total_threads = MINIMUM_THREADS_AMOUNT;
      }
    }    
  }
  return 1;

  #undef MINIMUM_THREADS_AMOUNT
  #undef database_reset
  #undef SET_PARAMETERS_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: print_settings
Description: Prints the delegates settings
-----------------------------------------------------------------------------------------------------------
*/

void print_settings(void)
{
  // Variables
  char buffer[SMALL_BUFFER_SIZE];

  int offset = 0; // To keep track of how many characters have been written

  offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Settings\n\nPublic Address: %s\n", xcash_wallet_public_address);
  offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\nBlock Verifiers Secret Key: %s\n", secret_key);
  offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\nDatabase Name: %s\n", database_name);

  if (shared_delegates_website == 1)
  {
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\nShared Delegate Settings: YES\nFee: %lf\n", fee);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\nMinimum Amount: %lld\n", minimum_amount);
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\nShared Delegates Database Name %s\n", shared_delegates_database_name);
  }
  else
  {
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\nShared Delegate Settings: NO\n");
  }

  if (delegates_website == 1) {
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Delegate Settings: YES\n");
  }else{
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Delegate Settings: NO\n");
  }

  if (log_file_settings == 0)
  {
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Log file Settings: NO\n");
  }
  else
  {
      if (log_file_settings == 1)
      {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Log file Settings: YES\nLog File Color Output: NO\n");
      }else{
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Log file Settings: YES\nLog File Color Output: YES\n");

      }
  }
  if (debug_settings == 1){
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Debug Settings: YES\n");
  }else{
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Debug Settings: NO\n");
  }

  if (network_data_node_settings){
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Mode: SEED NODE\n");
  }else{
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Mode: DELEGATE NODE\n");
  }

  offset += snprintf(buffer + offset, sizeof(buffer) - offset, "DPOPS Server: %s:%d\n", XCASH_DPOPS_delegates_IP_address, SEND_DATA_PORT);
  offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Daemon Node: %s:%d\n", XCASH_daemon_IP_address,XCASH_DAEMON_PORT);

  offset += snprintf(buffer + offset, sizeof(buffer) - offset, "XCASH Wallet: %s:%d\n", XCASH_wallet_IP_address, xcash_wallet_port);
  offset += snprintf(buffer + offset, sizeof(buffer) - offset, "MongoDB: %s:27017\n", MongoDB_IP_address);

  offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\nTotal Threads: %d\n", total_threads);

  color_print(buffer, "yellow");
}


/*
-----------------------------------------------------------------------------------------------------------
Name: start_timer_threads
Description: Starts the timer threads
-----------------------------------------------------------------------------------------------------------
*/

void start_timer_threads(void)
{
  // Variables
  char data[BUFFER_SIZE_NETWORK_BLOCK_DATA];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;

  // threads
  pthread_t thread_id[5];

  // define macros
  #define START_TIMER_THREADS_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"start_timer_threads",19); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  print_error_message(current_date_and_time,current_UTC_date_and_time,data); \
  mongoc_client_pool_destroy(database_client_thread_pool); \
  mongoc_uri_destroy(uri_thread_pool); \
  mongoc_cleanup(); \
  exit(0);

  memset(data,0,sizeof(data));

  print_start_message(current_date_and_time,current_UTC_date_and_time,"Starting all of the threads",data);

  // start the current block height timer thread
  if (pthread_create(&thread_id[0], NULL, &current_block_height_timer_thread, NULL) != 0 && pthread_detach(thread_id[0]) != 0)
  {
    START_TIMER_THREADS_ERROR("Could not start the current_block_height_timer_thread");
  }
  
  color_print("Started the current block height timer thread","green");

  // start the block height timer thread
  if (shared_delegates_website == 1)
  {
    if (pthread_create(&thread_id[3], NULL, &block_height_timer_thread, NULL) != 0 && pthread_detach(thread_id[3]) != 0)
    {
      START_TIMER_THREADS_ERROR("Could not start the block_height_timer_thread");
    }
  
    color_print("Started the shared delegates current block height timer thread","green");

    // start the payment timer thread
    if (pthread_create(&thread_id[4], NULL, &payment_timer_thread, NULL) != 0 && pthread_detach(thread_id[4]) != 0)
    {
      START_TIMER_THREADS_ERROR("Could not start the block_height_timer_thread");
    }
  
    color_print("Started the payment_timer_thread","green");
  }
  return;

  #undef START_TIMER_THREADS_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: main
Description: The start point of the program
Parameters:
  parameters_count - The parameter count
  parameters - The parameters
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int main(int parameters_count, char* parameters[])
{
    char data[SMALL_BUFFER_SIZE];
    memset(data,0,sizeof(data));

  // iniltize the random number generator
  srand((unsigned int)time(NULL));

  // Variables
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  int settings;
  
  // define macros
  #define MESSAGE "{\"username\":\"XCASH\"}"
  
  #define database_reset \
  mongoc_client_pool_destroy(database_client_thread_pool); \
  mongoc_uri_destroy(uri_thread_pool); \
  mongoc_cleanup();

  #define MAIN_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"start_registration_mode",23); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  print_error_message(current_date_and_time,current_UTC_date_and_time,data); \
  mongoc_client_pool_destroy(database_client_thread_pool); \
  mongoc_uri_destroy(uri_thread_pool); \
  mongoc_cleanup(); \
  exit(0);

  initialize_data(parameters_count, parameters);

  // write the message
  color_print(XCASH_DPOPS_CURRENT_VERSION,"green");

  // check if they want to display the parameters
  if (parameters_count == 2 && strncmp(parameters[1],"--parameters",BUFFER_SIZE) == 0)
  {
    printf(INVALID_PARAMETERS_ERROR_MESSAGE);
    exit(0);
  }

  if (parameters_count == 2 && strncmp(parameters[1],"--generate-key",BUFFER_SIZE) == 0)
  {
    generate_key();
    exit(0);
  }

  for (int param_idx = 0; param_idx < parameters_count; param_idx++)
  { 

    if (strncmp(parameters[param_idx],"--mongodb-ip-address",BUFFER_SIZE) == 0 && param_idx != parameters_count)
    {
      strncpy(MongoDB_IP_address,parameters[param_idx+1],sizeof(MongoDB_IP_address)-1);
      break;
    }
  }


  create_overall_database_connection();

  // brief check if database is empty
  if (count_db_delegates() <=0 || count_db_statistics() <=0) {
    MAIN_ERROR("'delegates' or 'statistics' DB not initialized. Do it manually");
  }

  settings = set_parameters(parameters_count, parameters);


  // get public address, current block height, previous hash and detect if it is the seed node. for current node
  get_node_data();

  // check if the test are running to change the VRF secret key
  
  memset(data, 0, sizeof(data));
  if (production_settings == 0)
    test_generate_secret_key();
    



  
  // check if it should create the default database data

  // FIXME: possible that is THE case when it deletes delegates DB. if some error happens
  // memset(data, 0, sizeof(data));
  // if ((read_document_field_from_collection(database_name, "statistics", MESSAGE, "username", data) == 0) ||
  //     (read_document_field_from_collection(database_name, "statistics", MESSAGE, "username", data) == 1 &&
  //      count_all_documents_in_collection(database_name, "delegates") < NETWORK_DATA_NODES_AMOUNT)) {
  //     delete_collection_from_database(database_name, "reserve_proofs_1");
  //     delete_collection_from_database(database_name, "delegates");
  //     delete_collection_from_database(database_name, "statistics");
  //     RESET_ERROR_MESSAGES;
  //     INITIALIZE_DATABASE_DATA(production_settings_database_data_settings);
  // }

  print_settings();

  // check if the wallets public address is loaded
  if (network_data_node_settings == 0 && strlen(xcash_wallet_public_address) != XCASH_WALLET_LENGTH)
  {
    MAIN_ERROR("Could not get the wallets public address");
  }

  // only network data nodes can use the registration mode
  if (registration_settings == 1 && network_data_node_settings == 0)
  {
    registration_settings = 0;
  }
 
  if (settings != 2)
  {
    initial_db_sync_check();
    RESET_ERROR_MESSAGES;
  }
  
  // start the server
  if (create_server(1) == 0)
  {
    MAIN_ERROR("Could not start the server");
  }
  
  /*// wait until the blockchain is fully synced
  color_print("Checking if the blockchain is fully synced","yellow");

  while (check_if_blockchain_is_fully_synced() == 0)
  {
    color_print("The blockchain is not fully synced.\nWaiting until it is fully synced to continue (This might take a while)","yellow"); 
    sleep(60);
  }*/

  if (settings != 2)
  {
    start_timer_threads();
  }

  for (;;)
  {
    sleep(10);
  }

  database_reset;
  return 0; 
  
  #undef MESSAGE
  #undef database_reset
  #undef MAIN_ERROR
}

