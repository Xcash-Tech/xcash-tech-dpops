
#include "init_processing.h"


void hex_to_byte_array(const char *hex_string, unsigned char *byte_array) {
    size_t len = strlen(hex_string);
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
    }
}

bool init_data_by_config(const arg_config_t *config) {

  // TODO: maybe it's better to add validation on the parse level
  if (config->block_verifiers_secret_key) {
    strncpy(secret_key,config->block_verifiers_secret_key,sizeof(secret_key)-1);
    hex_to_byte_array(secret_key,secret_key_data);
  }

  // set DPoPS database name
  strncpy(database_name,config->database_name?config->database_name:DATABASE_NAME,sizeof(database_name)-1);

  // set shared delegates database name
  strncpy(shared_delegates_database_name,config->shared_delegates_database_name?config->shared_delegates_database_name:DATABASE_NAME_DELEGATES,sizeof(database_name)-1);


  // set total threads
  total_threads = config->total_threads? config->total_threads: get_nprocs();

  // set debug mode
  debug_settings = config->debug_mode? 1: 0;
  delegates_error_list_settings = config->debug_delegates_error? 1: 0;

  // set website params
  delegates_website = config->delegates_website? 1:0;
  shared_delegates_website = config->shared_delegates_website? 1:0;

  // set minumum payout amount. default is 0
  // FIXME: maybe it's wrong logic and better set something more valuable than 0
  minimum_amount = config->minimum_amount? config->minimum_amount: 0;

  // set delegate fee
  fee = (int)config->fee == 0? 0: config->fee;

  // set inactivity count
  if (config->voter_inactivity_count) {
    snprintf(voter_inactivity_count,sizeof(voter_inactivity_count),"%d", config->voter_inactivity_count);
  }else {
    strncpy(voter_inactivity_count,VOTER_INACTIVITY_COUNT,sizeof(voter_inactivity_count)-1);
  }

  // set RPC IP's
  strncpy(XCASH_DPOPS_delegates_IP_address, config->delegates_ip_address?config->delegates_ip_address:"127.0.0.1", sizeof(XCASH_DPOPS_delegates_IP_address)-1);

  strncpy(XCASH_daemon_IP_address, config->xcash_daemon_ip_address?config->xcash_daemon_ip_address:"127.0.0.1", sizeof(XCASH_daemon_IP_address)-1);

  strncpy(XCASH_wallet_IP_address, config->xcash_wallet_ip_address?config->xcash_wallet_ip_address:"127.0.0.1", sizeof(XCASH_wallet_IP_address)-1);
  
  xcash_wallet_port = config->xcash_wallet_port?config->xcash_wallet_port:XCASH_WALLET_PORT;


  // set logging
  log_file_settings = 0;
  if (config->log_file_name) {
    log_file_settings = 1;
    strncpy(log_file, config->log_file_name, sizeof(log_file)-1);
  }

  if (config->log_file_name_color) {
    log_file_settings = 2;
    strncpy(log_file, config->log_file_name_color, sizeof(log_file)-1);
  }

  if (config->server_log_file) {
    server_log_fp = fopen(config->server_log_file, "a");
    if (!server_log_fp) {
      ERROR_PRINT("Can't create server log file %s",config->server_log_file);
      return false;
    };
    log_add_fp(server_log_fp, 0);
    log_set_quiet(true);
    log_info("Xcash DPoPS servers logs");
  }


  // set and load private group
  private_group.private_group_settings = 0; 
  if (config->private_group) {
    private_group.private_group_settings = 1; 
    strncpy(private_group.private_group_file, config->private_group, sizeof(private_group.private_group_file)-1);
    if (load_private_group_configuration() == 0)
    {
      ERROR_PRINT("The private group file could not be loaded");
      return false;
    } 
  }

    // TODO move website processing to other service
    // get the website path

    char data[SMALL_BUFFER_SIZE];
    memset(website_path, 0, sizeof(website_path));
    memset(data, 0, sizeof(data));
    if (readlink("/proc/self/exe", data, sizeof(data)) == -1) {
        ERROR_PRINT("Could not get the websites path");
        return false;
    }
    memcpy(website_path, data, strnlen(data, sizeof(website_path)) - 17);
    delegates_website == 1
        ? memcpy(website_path + strlen(website_path), DELEGATES_WEBSITE_PATH, sizeof(DELEGATES_WEBSITE_PATH) - 1)
        : memcpy(website_path + strlen(website_path), SHARED_DELEGATES_WEBSITE_PATH,
                 sizeof(SHARED_DELEGATES_WEBSITE_PATH) - 1);


  return true;
}


void initialize_data_structures(void)
{
  // Variables
  char data[SMALL_BUFFER_SIZE];
  size_t count = 0;

  srand(time(NULL));


  memset(delegates_all, 0, sizeof(delegates_all));

  memset(data,0,sizeof(data));

  // make sure the threads are NULL
  memset(server_threads,0,sizeof(server_threads));

  // initialize the global variables
  memset(current_block_height,0,sizeof(current_block_height));
  memset(current_round_part,0,sizeof(current_round_part));
  memset(current_round_part_backup_node,0,sizeof(current_round_part_backup_node));
  

  // set the current_round_part, current_round_part_backup_node and server message, this way the node will start at the begining of a round
  memset(current_round_part,0,sizeof(current_round_part));
  memset(current_round_part_backup_node,0,sizeof(current_round_part_backup_node));
  memcpy(current_round_part,"1",sizeof(char));
  memcpy(current_round_part_backup_node,"0",sizeof(char));



  memset(database_path_write,0,sizeof(database_path_write));
  memset(database_path_write_before_majority,0,sizeof(database_path_write_before_majority));
  memset(database_path_read,0,sizeof(database_path_read));


  // initialize the private group and load it on execution level
  private_group.private_group_settings = 0;

  test_settings = 0;

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
  pthread_mutex_init(&hash_mutex, NULL);


  server_limit_IP_address_list = (char*)calloc(15728640,sizeof(char)); // 15 MB
  server_limit_public_address_list = (char*)calloc(15728640,sizeof(char)); // 15 MB
   
  // check if the memory needed was allocated on the heap successfully
  if (server_limit_IP_address_list == NULL || server_limit_public_address_list == NULL)
  {
    FATAL_ERROR_EXIT("Can't allocate memory");
  }

  // initialize the error_message struct
  for (count = 0; count < TOTAL_ERROR_MESSAGES; count++)
  {
    error_message.function[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
    error_message.data[count] = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));

    if (error_message.function[count] == NULL || error_message.data[count] == NULL)
    {
      FATAL_ERROR_EXIT("Can't allocate memory");
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
    FATAL_ERROR_EXIT("Can't allocate memory");
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
      FATAL_ERROR_EXIT("Can't allocate memory");
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
    FATAL_ERROR_EXIT("Can't allocate memory");
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
      FATAL_ERROR_EXIT("Can't allocate memory");
    }
  }
  blockchain_data.ringct_version_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));
  blockchain_data.transaction_amount_data = (char*)calloc(BUFFER_SIZE_NETWORK_BLOCK_DATA,sizeof(char));

  // FIXME removed repetitive memory allocation. check what's with transactions
  // for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++)
  // {
  //   blockchain_data.transactions[count] = (char*)calloc(TRANSACTION_HASH_LENGTH+1,sizeof(char));

  //   // check if the memory needed was allocated on the heap successfully
  //   if (blockchain_data.transactions[count] == NULL)
  //   {
  //     FATAL_ERROR_EXIT("Can't allocate memory");
  //   }
  // }

  invalid_reserve_proofs.count = 0;

  for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++)
  {
    blockchain_data.transactions[count] = (char*)calloc(TRANSACTION_HASH_LENGTH+1,sizeof(char));

    // check if the memory needed was allocated on the heap successfully
    if (blockchain_data.transactions[count] == NULL)
    {
      FATAL_ERROR_EXIT("Can't allocate memory");
    }
  }

  // initialize the network data nodes
  INITIALIZE_NETWORK_DATA_NODES;
  return;

}

void cleanup_data_structures(void) {
    size_t count;
    pthread_mutex_destroy(&lock);
    pthread_mutex_destroy(&database_lock);
    pthread_mutex_destroy(&verify_network_block_lock);
    pthread_mutex_destroy(&vote_lock);
    pthread_mutex_destroy(&add_reserve_proof_lock);
    pthread_mutex_destroy(&invalid_reserve_proof_lock);
    pthread_mutex_destroy(&database_data_IP_address_lock);
    pthread_mutex_destroy(&update_current_block_height_lock);
    pthread_rwlock_destroy(&rwlock_reserve_proofs);
    pthread_rwlock_destroy(&rwlock);
    
    pthread_mutex_destroy(&hash_mutex);

    free(server_limit_IP_address_list);
    free(server_limit_public_address_list);

    // initialize the error_message struct
    for (count = 0; count < TOTAL_ERROR_MESSAGES; count++) {
        free(error_message.function[count]);
        free(error_message.data[count]);
    }

    // initialize the VRF_data struct
    free(VRF_data.vrf_secret_key_data);
    free(VRF_data.vrf_secret_key);
    free(VRF_data.vrf_public_key_data);
    free(VRF_data.vrf_public_key);
    free(VRF_data.vrf_alpha_string_data);
    free(VRF_data.vrf_alpha_string);
    free(VRF_data.vrf_proof_data);
    free(VRF_data.vrf_proof);
    free(VRF_data.vrf_beta_string_data);
    free(VRF_data.vrf_beta_string);
    free(VRF_data.block_blob);
    free(VRF_data.reserve_bytes_data_hash);

    // check if the memory needed was allocated on the heap successfully

    for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++) {
        free(VRF_data.block_verifiers_vrf_secret_key_data[count]);
        free(VRF_data.block_verifiers_vrf_secret_key[count]);
        free(VRF_data.block_verifiers_vrf_public_key_data[count]);
        free(VRF_data.block_verifiers_vrf_public_key[count]);
        free(VRF_data.block_verifiers_random_data[count]);
        free(VRF_data.block_blob_signature[count]);
    }

    // initialize the blockchain_data struct
    free(blockchain_data.network_version_data);
    free(blockchain_data.timestamp_data);
    free(blockchain_data.previous_block_hash_data);
    free(blockchain_data.nonce_data);
    free(blockchain_data.block_reward_transaction_version_data);
    free(blockchain_data.unlock_block_data);
    free(blockchain_data.block_reward_input_data);
    free(blockchain_data.vin_type_data);
    free(blockchain_data.block_height_data);
    free(blockchain_data.block_reward_output_data);
    free(blockchain_data.block_reward_data);
    free(blockchain_data.stealth_address_output_tag_data);
    free(blockchain_data.stealth_address_output_data);
    free(blockchain_data.extra_bytes_size_data);
    free(blockchain_data.transaction_public_key_tag_data);
    free(blockchain_data.transaction_public_key_data);
    free(blockchain_data.extra_nonce_tag_data);
    free(blockchain_data.reserve_bytes_size_data);
    free(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name_data);
    free(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name);
    free(blockchain_data.blockchain_reserve_bytes.block_producer_public_address_data);
    free(blockchain_data.blockchain_reserve_bytes.block_producer_public_address);
    free(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count_data);
    free(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count);
    free(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names_data);
    free(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names);
    free(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data);
    free(blockchain_data.blockchain_reserve_bytes.vrf_secret_key);
    free(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data);
    free(blockchain_data.blockchain_reserve_bytes.vrf_public_key);
    free(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data);
    free(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string);
    free(blockchain_data.blockchain_reserve_bytes.vrf_proof_data);
    free(blockchain_data.blockchain_reserve_bytes.vrf_proof);
    free(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data);
    free(blockchain_data.blockchain_reserve_bytes.vrf_beta_string);
    free(blockchain_data.blockchain_reserve_bytes.vrf_data_round);
    free(blockchain_data.blockchain_reserve_bytes.vrf_data);
    free(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data);

    for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++) {
        free(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address_data[count]);
        free(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count]);
        free(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count]);
        free(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count]);
        free(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count]);
        free(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count]);
        free(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count]);
        free(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count]);
        free(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count]);
        free(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count]);
    }
    free(blockchain_data.ringct_version_data);
    free(blockchain_data.transaction_amount_data);

    // for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++)
    // {
    //   free(  blockchain_data.transactions[count]);
    // }

    for (count = 0; count < MAXIMUM_TRANSACATIONS_PER_BLOCK; count++) {
        free(blockchain_data.transactions[count]);
    }
}

/*
-----------------------------------------------------------------------------------------------------------
Name: print_settings
Description: Prints the delegates settings
-----------------------------------------------------------------------------------------------------------
*/




static char xcash_tech_header[] = "\n"
" /$$   /$$                           /$$      /$$$$$$$$               /$$      \n"
"| $$  / $$                          | $$     |__  $$__/              | $$      \n"
"|  $$/ $$/ /$$$$$$$ /$$$$$$  /$$$$$$| $$$$$$$   | $$ /$$$$$$  /$$$$$$| $$$$$$$ \n"
" \\  $$$$/ /$$_____/|____  $$/$$_____| $$__  $$  | $$/$$__  $$/$$_____| $$__  $$\n"
"  /$$  $$| $$       /$$$$$$|  $$$$$$| $$  \\ $$  | $| $$$$$$$| $$     | $$  \\ $$\n"
" /$$/\\  $| $$      /$$__  $$\\____  $| $$  | $$  | $| $$_____| $$     | $$  | $$\n"
"| $$  \\ $|  $$$$$$|  $$$$$$$/$$$$$$$| $$  | $$/$| $|  $$$$$$|  $$$$$$| $$  | $$\n"
"|__/  |__/\\_______/\\_______|_______/|__/  |__|__|__/\\_______/\\_______|__/  |__/\n"
"\n";

#define xcash_tech_status_fmt "ver.(%s) %s\n\n"\
"Address:\t%s\n"\
"\n"\
"Node Type:\t%s\n"\
"\n"\
"Services:\n"\
"Daemon:\t\t%s:%d\n"\
"DPoPS:\t\t%s:%d\n"\
"Wallet:\t\t%s:%d\n"\
"MongoDB:\t%s\n"



void print_starter_state(void)
{
    fprintf(stderr, "%s",xcash_tech_header);
    fprintf(stderr, xcash_tech_status_fmt,
        "1.3.0","~Next",
        xcash_wallet_public_address,
        is_seed_node? "SEED NODE": "DELEGATE NODE",
        XCASH_daemon_IP_address, XCASH_DAEMON_PORT,
        XCASH_DPOPS_delegates_IP_address, XCASH_DPOPS_PORT,
        XCASH_wallet_IP_address, XCASH_WALLET_PORT,
        MongoDB_uri);
}

bool timer_threads_init(void) {
    // Variables
    char data[BUFFER_SIZE_NETWORK_BLOCK_DATA];
    // time_t current_date_and_time;
    // struct tm current_UTC_date_and_time;

    // threads
    pthread_t thread_id[5];

    memset(data, 0, sizeof(data));

    // print_start_message(current_date_and_time, current_UTC_date_and_time, "Starting all of the threads", data);

    // // start the current block height timer thread
    // if (pthread_create(&thread_id[0], NULL, &current_block_height_timer_thread, NULL) != 0 &&
    //     pthread_detach(thread_id[0]) != 0) {
    //     ERROR_PRINT("Could not start the current_block_height_timer_thread");
    //     return false;
    // }

    if (!is_seed_node) {
        // start the block height timer thread
        if (shared_delegates_website == 1) {
            if (pthread_create(&thread_id[3], NULL, &block_height_timer_thread, NULL) != 0 &&
                pthread_detach(thread_id[3]) != 0) {
                ERROR_PRINT("Could not start the block_height_timer_thread");
                return false;
            }

            color_print("Started the shared delegates current block height timer thread", "green");

            // start the payment timer thread
            if (pthread_create(&thread_id[4], NULL, &payment_timer_thread, NULL) != 0 &&
                pthread_detach(thread_id[4]) != 0) {
                ERROR_PRINT("Could not start the payment_timer_thread");
                return false;
            }

            color_print("Started the payment_timer_thread", "green");
        }
    }

    return true;
}


void check_for_dpops_block_height(void) {
    size_t block_height;
    sscanf(current_block_height, "%zu", &block_height);

    while (block_height < XCASH_PROOF_OF_STAKE_BLOCK_HEIGHT) {
        INFO_PRINT("Xcash Daemon is not fully synced. Waiting for DPoPS block. Currently on %ld block", block_height);
        get_current_block_height(current_block_height);
        sscanf(current_block_height, "%zu", &block_height);
        sleep(5);
    }
}



bool processing(const arg_config_t *arg_config) {
    initialize_data_structures();

    if (!init_data_by_config(arg_config)) {
        ERROR_PRINT("Check command line parameters");
        cleanup_data_structures();
        return false;
    };

    // if (arg_config->sync_dbs_from_node) return synchronize_database_from_network_data_node();

    // if (arg_config->sync_dbs_from_delegate_ip) return synchronize_database_from_network_data_node();

    // brief check if database is empty
    if (count_db_delegates() <= 0 || count_db_statistics() <= 0) {
        ERROR_PRINT("'delegates' or 'statistics' DB not initialized. Do it manually");
        cleanup_data_structures();
        return false;
    }

    // get public address, and detect if it is the seed node
    if (!get_node_data()) {
        DEBUG_PRINT("Can't get node initial information");
        cleanup_data_structures();
        return false;
    }



    print_starter_state();

    if (!get_daemon_data()) {
        DEBUG_PRINT("Can't get daemon data");
    }

    // just in case of the daemon did't synced well before
    check_for_dpops_block_height();


    if (!check_time_sync_to_seeds()) {
        ERROR_PRINT("The node has significant time difference with seed nodes. " ORANGE_TEXT("Fix it!"));
        cleanup_data_structures();
        return false;
    }

    if (!fill_delegates_from_db()) {
        ERROR_PRINT("Can't read delegates list from DB");
        cleanup_data_structures();
        return false;
    }

    INFO_STAGE_PRINT("Checking that the node has actual db hashes");

    // do it here because initial calculation could take a long time
    xcash_node_sync_info_t sync_info;
    if (!get_node_sync_info(&sync_info)) {
        ERROR_PRINT("Can't get local sync info");
        return false;
    }

    INFO_PRINT_STATUS_OK("Hashes checked");


    INFO_STAGE_PRINT("Starting network initialisation loop...");

    network_recovery_state = false;
    bool server_started = false;
    size_t network_majority_count = 0;
    // do the synchronization until the network reach majority
    do
    {

      if (network_recovery_state) {
        INFO_STAGE_PRINT("Waiting 10s for Network Recovery before continuing...");
        sleep(10);

      }

      // FIXME possible dead end if node has not synced blockchain. it will not return right data to
      // to other nodes. and if there is not enough working nodes we could loop
      // but we need to start server anyway
      if (!get_daemon_data()) {
          network_recovery_state =  true;
          WARNING_PRINT("Can't get node daemon data");
      }


      // check if are online of no
      bool is_seeds_offline = (get_network_data_nodes_online_status() == 0);
    
      // load actual nodes list
      if (get_actual_nodes_list(is_seeds_offline)) {
        if (initial_db_sync_check(&network_majority_count, NULL)) {
            INFO_PRINT_STATUS_OK("Initial database sync check finished successfully");
            if (network_majority_count >= BLOCK_VERIFIERS_VALID_AMOUNT) {
              network_recovery_state = false;
            }else {
              network_recovery_state = true;
              
              WARNING_PRINT("Not enough nodes online for block production start. Please wait for a full network recovery");
            }
        } else {
          WARNING_PRINT("Can't sync databases. Please wait for network recovery to complete");
          network_recovery_state = true;
        }
      } else {
          WARNING_PRINT("Can't get node active nodes list");
          network_recovery_state = true;
      }

      // we need the server to be online to allow other nodes get node data to reach majority even if node is not fully synced yet
      if (!server_started) {
        // start the server
        if (!create_server()) {
            ERROR_PRINT("Could not start the server");
            cleanup_data_structures();
            return false;
        }
        server_started =  true;
      }
    }while (network_recovery_state);
    
      
    // start all other services
    if (!timer_threads_init()) {
        cleanup_data_structures();
        return false;
    }

    return true;
}
