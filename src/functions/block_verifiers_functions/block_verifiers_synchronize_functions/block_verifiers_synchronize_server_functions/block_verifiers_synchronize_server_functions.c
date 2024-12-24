#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>

#include "define_macro_functions.h"
#include "define_macros.h"
#include "initialize_and_reset_structs_define_macros.h"
#include "structures.h"
#include "variables.h"
#include "define_macros_test.h"

#include "blockchain_functions.h"
#include "block_verifiers_synchronize_server_functions.h"
#include "block_verifiers_thread_server_functions.h"
#include "block_verifiers_update_functions.h"
#include "database_functions.h"
#include "read_database_functions.h"
#include "update_database_functions.h"
#include "file_functions.h"
#include "network_daemon_functions.h"
#include "network_functions.h"
#include "network_security_functions.h"
#include "network_wallet_functions.h"
#include "server_functions.h"
// #include "organize_functions.h"
#include "string_functions.h"
#include "thread_functions.h"
#include "convert.h"
#include "vrf.h"
#include "crypto_vrf.h"
#include "VRF_functions.h"
#include "sha512EL.h"

#include "db_operations.h"
#include "log.h"
#include "xcash_message.h"
#include "xcash_db_sync.h"
#include "round.h"
#include "xcash_db_helpers.h"
#include <jansson.h>

/*
-----------------------------------------------------------------------------------------------------------
Functions
-----------------------------------------------------------------------------------------------------------
*/

bool get_block_hash(unsigned long block_height, char* block_hash, size_t block_hash_size) {
  char db_collection_name[DB_COLLECTION_NAME_SIZE];
  char block_height_str[DB_COLLECTION_NAME_SIZE];

  unsigned long reserve_bytes_db_index = ((block_height - XCASH_PROOF_OF_STAKE_BLOCK_HEIGHT) / BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME) + 1;

  sprintf(db_collection_name, "reserve_bytes_%zu", reserve_bytes_db_index);
  sprintf(block_height_str, "%zu", block_height);

  bson_error_t error;
  bson_t *filter = BCON_NEW("block_height", BCON_UTF8(block_height_str));
  bson_t *doc = bson_new();
  if (!db_find_doc(database_name, db_collection_name, filter, doc, &error)) {
    log_error("Failed to find document: %s", error.message);
    bson_destroy(filter);
    bson_destroy(doc);
    return false;
  }

  char *str = bson_as_canonical_extended_json(doc, NULL);
  log_info("Found document: %s", str);
  bson_free(str);

  bson_iter_t iter;
  if (bson_iter_init(&iter, doc) && bson_iter_find_descendant(&iter, "0.reserve_bytes_data_hash", &iter) && BSON_ITER_HOLDS_UTF8(&iter)) {
    const char *hash = bson_iter_utf8(&iter, NULL);
    strncpy(block_hash, hash, block_hash_size - 1);
    block_hash[block_hash_size - 1] = '\0';
  } else {
    log_error("block_hash not found in document");
    bson_destroy(filter);
    bson_destroy(doc);
    return false;
  }

  bson_destroy(filter);
  bson_destroy(doc);
  return true;
}


void server_received_msg_get_block_hash(const int CLIENT_SOCKET, const char* MESSAGE)
{
    (void)MESSAGE;
    (void)CLIENT_SOCKET;

    log_info("received %s, %s", __func__, "XCASH_GET_BLOCK_HASH");

    json_error_t error;
    json_t *json_message = json_loads(MESSAGE, 0, &error);
    if (!json_message) {
      log_error("Error parsing JSON: %s", error.text);
      return;
    }

    json_t *block_height_json = json_object_get(json_message, "block_height");
    if (!json_is_integer(block_height_json)) {
      log_error("block_height is not an integer");
      json_decref(json_message);
      return;
    }

    unsigned long block_height = (unsigned long)json_integer_value(block_height_json);
    json_decref(json_message);


    // find block hash
    const char block_hash[DATA_HASH_LENGTH + 1];
    if (!get_block_hash(block_height, block_hash, sizeof(block_hash))) {
      log_error("Failed to get block hash for block height %lu", block_height);
      return;
    }

    json_t *reply_json = json_object();

    json_object_set_new(reply_json, "message_settings", json_string("XCASH_GET_BLOCK_PRODUCERS"));
    json_object_set_new(reply_json, "public_address", json_string(xcash_wallet_public_address));
    json_object_set_new(reply_json, "block_hash", json_string(block_hash));


    char* message_result_data = json_dumps(reply_json, JSON_COMPACT);
    json_decref(reply_json);

    size_t message_result_size =  strlen(message_result_data);

    message_result_data = realloc(message_result_data, message_result_size + sizeof(SOCKET_END_STRING));
    strcat(message_result_data, SOCKET_END_STRING);


    send_data(CLIENT_SOCKET,(unsigned char*)message_result_data,0,0,"");
    free(message_result_data);

}



void server_received_msg_get_block_producers(const int CLIENT_SOCKET, const char* MESSAGE)
{
    (void)MESSAGE;
    (void)CLIENT_SOCKET;

    log_info("received %s, %s", __func__, "XCASH_GET_BLOCK_PRODUCERS");


    json_t *reply_json = json_object();

    json_object_set_new(reply_json, "message_settings", json_string("XCASH_GET_BLOCK_PRODUCERS"));
    json_object_set_new(reply_json, "public_address", json_string(xcash_wallet_public_address));

    json_t* producers_array = json_array();
    json_t* producers_ip_array = json_array();

    for (size_t i = 0; i < BLOCK_VERIFIERS_TOTAL_AMOUNT; i++) {
        if (strcmp(delegates_all[i].online_status, "true") == 0) {
            json_array_append_new(producers_array, json_string(delegates_all[i].public_address));
            json_array_append_new(producers_ip_array, json_string(delegates_all[i].IP_address));
        }
    }
    json_object_set_new(reply_json, "producers", producers_array);
    json_object_set_new(reply_json, "producers_ip", producers_ip_array);


    char* message_result_data = json_dumps(reply_json, JSON_COMPACT);
    json_decref(reply_json);

    size_t message_result_size =  strlen(message_result_data);

    message_result_data = realloc(message_result_data, message_result_size + sizeof(SOCKET_END_STRING));
    strcat(message_result_data, SOCKET_END_STRING);


    send_data(CLIENT_SOCKET,(unsigned char*)message_result_data,0,0,"");
    free(message_result_data);

}



void server_received_msg_get_sync_info(const int CLIENT_SOCKET, const char* MESSAGE)
{
    (void)MESSAGE;
    log_info("received %s, %s", __func__, "XCASH_GET_SYNC_INFO");

    xcash_node_sync_info_t sync_info;
    if (!get_node_sync_info(&sync_info)) {
        ERROR_PRINT("Can't set sync info");
        return;
    }

    if (!sync_info.db_reserve_bytes_synced) {
      log_info("Local Reserve bytes DB is not fully synced. Will not respond");
      return;
    }
  
    char dn_field_names[DATABASE_TOTAL][DB_COLLECTION_NAME_SIZE + 1];
    char block_height_str[DB_COLLECTION_NAME_SIZE + 1];

    sprintf(block_height_str,"%ld",sync_info.block_height);

    const char **param_list = calloc(DATABASE_TOTAL + 1 + 1 + 1, sizeof(char *) * 2);
    int param_index = 0;

    param_list[param_index++] = "block_height";
    param_list[param_index++] = block_height_str;

    param_list[param_index++] = "public_address";
    param_list[param_index++] = xcash_wallet_public_address;

    for (size_t i = 0; i < DATABASE_TOTAL; i++) {
      sprintf(dn_field_names[i],"data_hash_%s", collection_names[i]);
      param_list[param_index++] = dn_field_names[i];
      param_list[param_index++] = sync_info.db_hashes[i];
    }

    char* message_data = create_message_param_list(XMSG_XCASH_GET_SYNC_INFO, param_list);
    free(param_list);  

    if (message_data) {
      message_data = realloc(message_data,strlen(message_data)+sizeof(SOCKET_END_STRING)+1);
      strcat(message_data,SOCKET_END_STRING);

      // send the data
      send_data(CLIENT_SOCKET,(unsigned char*)message_data,0,0,"");
      free(message_data);
    }

}

/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_get_current_block_height
Description: Runs the code when the server receives the GET_CURRENT_BLOCK_HEIGHT message
Parameters:
  CLIENT_IP_ADDRESS - The IP address to send the data to
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_get_current_block_height(const char* CLIENT_IP_ADDRESS)
{
  // Variables
  char data[SMALL_BUFFER_SIZE];

  log_info("received %s, %s", __func__, "GET_CURRENT_BLOCK_HEIGHT");
  memset(data,0,sizeof(data));

  // create the message
  memcpy(data,"{\r\n \"message_settings\": \"SEND_CURRENT_BLOCK_HEIGHT\",\r\n \"block_height\": \"",72);
  memcpy(data+strlen(data),current_block_height,strnlen(current_block_height,sizeof(current_block_height)));
  memcpy(data+strlen(data),"\",\r\n}",5);
  
  // sign_data
  if (sign_data(data) == 0)
  { 
    return;
  }

  send_data_socket(CLIENT_IP_ADDRESS,SEND_DATA_PORT,data,SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS);
  return;
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_send_current_block_height
Description: Runs the code when the server receives the SEND_CURRENT_BLOCK_HEIGHT message
Parameters:
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_send_current_block_height(const char* MESSAGE)
{
  // Variables
  char data[SMALL_BUFFER_SIZE];
  char public_address[XCASH_WALLET_LENGTH+1];
  char block_height[100];
  int count;
  size_t count2;

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_SEND_CURRENT_BLOCK_HEIGHT_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_send_current_block_height",52); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  return;

  memset(data,0,sizeof(data));
  memset(public_address,0,sizeof(public_address));
  memset(block_height,0,sizeof(block_height));

  // parse the message
  if (parse_json_data(MESSAGE,"block_height",block_height,sizeof(block_height)) == 0 || parse_json_data(MESSAGE,"public_address",public_address,sizeof(public_address)) == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_SEND_CURRENT_BLOCK_HEIGHT_ERROR("Could not parse the data");
  }

  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],public_address,BUFFER_SIZE) == 0)
    {
      sscanf(block_height,"%zu",&count2);
      block_verifiers_current_block_height[count] = count2;
      break;
    }
  }
  return;

  #undef SERVER_RECEIVE_DATA_SOCKET_SEND_CURRENT_BLOCK_HEIGHT_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_node_to_network_data_nodes_get_previous_current_next_block_verifiers_list
Description: Runs the code when the server receives the NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST message
Parameters:
  CLIENT_SOCKET - The socket to send data to
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_node_to_network_data_nodes_get_previous_current_next_block_verifiers_list(const int CLIENT_SOCKET)
{
  // Variables
  char data[BUFFER_SIZE];
  int count;
  size_t total_delegates = 0;

  log_info("received %s, %s", __func__, "NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST");

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_node_to_network_data_nodes_get_previous_current_next_block_verifiers_list",100); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  ERROR_DATA_MESSAGE;

  #define COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA(settings,block_verifiers_data) \
  memcpy(data+strlen(data),"\",\r\n \"",6); \
  memcpy(data+strlen(data),(settings),sizeof((settings))-1); \
  memcpy(data+strlen(data),"\": \"",4); \
  for (count = 0; count < (int)total_delegates; count++) \
  { \
    memcpy(data+strlen(data),(block_verifiers_data)[count],strnlen((block_verifiers_data)[count],sizeof(data))); \
    memcpy(data+strlen(data),"|",sizeof(char)); \
  }

  memset(data,0,sizeof(data));

  // get the delegate amount
  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    if (strlen(current_block_verifiers_list.block_verifiers_public_address[count]) != XCASH_WALLET_LENGTH)
    {
      total_delegates = count;
      break;
    }
  } 

  // create the message
  memcpy(data,"{\r\n \"message_settings\": \"NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST",98);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("previous_block_verifiers_name_list",previous_block_verifiers_list.block_verifiers_name);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("previous_block_verifiers_public_address_list",previous_block_verifiers_list.block_verifiers_public_address);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("previous_block_verifiers_public_key_list",previous_block_verifiers_list.block_verifiers_public_key);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("previous_block_verifiers_IP_address_list",previous_block_verifiers_list.block_verifiers_IP_address);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("current_block_verifiers_name_list",current_block_verifiers_list.block_verifiers_name);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("current_block_verifiers_public_address_list",current_block_verifiers_list.block_verifiers_public_address);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("current_block_verifiers_public_key_list",current_block_verifiers_list.block_verifiers_public_key);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("current_block_verifiers_IP_address_list",current_block_verifiers_list.block_verifiers_IP_address);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("next_block_verifiers_name_list",next_block_verifiers_list.block_verifiers_name);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("next_block_verifiers_public_address_list",next_block_verifiers_list.block_verifiers_public_address);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("next_block_verifiers_public_key_list",next_block_verifiers_list.block_verifiers_public_key);
  COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("next_block_verifiers_IP_address_list",next_block_verifiers_list.block_verifiers_IP_address);
  memcpy(data+strlen(data),"\",\r\n}",5);
  
  // sign_data
  if (sign_data(data) == 0)
  { 
    SERVER_RECEIVE_DATA_SOCKET_NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_ERROR("Could not sign data");
  }

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");
  return;

  #undef SERVER_RECEIVE_DATA_SOCKET_NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_ERROR
  #undef COPY_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_node_to_network_data_nodes_get_current_block_verifiers_list
Description: Runs the code when the server receives the NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST message
Parameters:
  CLIENT_SOCKET - The socket to send data to
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_node_to_network_data_nodes_get_current_block_verifiers_list(const int CLIENT_SOCKET)
{
  // Variables
  char data[BUFFER_SIZE];
  int count;

  log_info("received %s, %s", __func__, "NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST");

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_node_to_network_data_nodes_get_current_block_verifiers_list",86); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  send_data(CLIENT_SOCKET,(unsigned char*)"Could not get a list of the current block verifiers",0,1,""); \
  return;
  
  memset(data,0,sizeof(data));

  // create the message
  memcpy(data,"{\r\n \"message_settings\": \"NETWORK_DATA_NODE_TO_NODE_SEND_CURRENT_BLOCK_VERIFIERS_LIST\",\r\n \"block_verifiers_public_address_list\": \"",129);
  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    if (strlen(current_block_verifiers_list.block_verifiers_public_address[count]) == XCASH_WALLET_LENGTH)
    {
      memcpy(data+strlen(data),current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH);
      memcpy(data+strlen(data),"|",sizeof(char));
    }
  }
  memcpy(data+strlen(data),"\",\r\n \"block_verifiers_public_key_list\": \"",41);
  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    if (strlen(current_block_verifiers_list.block_verifiers_public_address[count]) == XCASH_WALLET_LENGTH)
    {
      memcpy(data+strlen(data),current_block_verifiers_list.block_verifiers_public_key[count],VRF_PUBLIC_KEY_LENGTH);
      memcpy(data+strlen(data),"|",sizeof(char));
    }
  }
  memcpy(data+strlen(data),"\",\r\n \"block_verifiers_IP_address_list\": \"",41);
  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    if (strlen(current_block_verifiers_list.block_verifiers_public_address[count]) == XCASH_WALLET_LENGTH)
    {
      memcpy(data+strlen(data),current_block_verifiers_list.block_verifiers_IP_address[count],strnlen(current_block_verifiers_list.block_verifiers_IP_address[count],sizeof(data)));
      memcpy(data+strlen(data),"|",sizeof(char));
    }
  }
  memcpy(data+strlen(data),"\",\r\n}",5);
  
  // sign_data
  if (sign_data(data) == 0)
  { 
    SERVER_RECEIVE_DATA_SOCKET_NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST_ERROR("Could not sign data");
  }
  
  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");
  return;

  #undef SERVER_RECEIVE_DATA_SOCKET_NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_network_data_nodes_to_network_data_nodes_database_sync_check
Description: Runs the code when the server receives the NETWORK_DATA_NODES_TO_NETWORK_DATA_NODES_DATABASE_SYNC_CHECK message
Parameters:
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_network_data_nodes_to_network_data_nodes_database_sync_check(const char* MESSAGE)
{
  // Variables
  char data_hash[DATABASE_TOTAL][DATA_HASH_LENGTH+1];
  char public_address[XCASH_WALLET_LENGTH+1];
  char data[SMALL_BUFFER_SIZE];
  int count;
  int count2;

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_NETWORK_DATA_NODES_TO_NETWORK_DATA_NODES_DATABASE_SYNC_CHECK_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_network_data_nodes_to_network_data_nodes_database_sync_check",87); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  return;

  memset(data,0,sizeof(data));
  memset(public_address,0,sizeof(public_address));

  for (count = 0; count < DATABASE_TOTAL; count++)
  {
    memset(data_hash[count],0,sizeof(data_hash[count]));
  }

  // parse the message
  if (registration_settings == 0)
  {
    if (parse_json_data(MESSAGE,"public_address",public_address,sizeof(public_address)) == 0 || parse_json_data(MESSAGE,"data_hash_reserve_proofs",data_hash[0],DATA_HASH_LENGTH) == 0 || parse_json_data(MESSAGE,"data_hash_reserve_bytes",data_hash[1],DATA_HASH_LENGTH) == 0 || parse_json_data(MESSAGE,"data_hash_delegates",data_hash[2],DATA_HASH_LENGTH) == 0 || parse_json_data(MESSAGE,"data_hash_statistics",data_hash[3],DATA_HASH_LENGTH) == 0 || parse_json_data(MESSAGE,"previous_blocks_reserve_bytes",data,sizeof(data)) == 0)
    {
      SERVER_RECEIVE_DATA_SOCKET_NETWORK_DATA_NODES_TO_NETWORK_DATA_NODES_DATABASE_SYNC_CHECK_ERROR("Could not parse the message");
    }
  }
  else
  {
    if (parse_json_data(MESSAGE,"public_address",public_address,sizeof(public_address)) == 0 || parse_json_data(MESSAGE,"data_hash",data_hash[0],DATA_HASH_LENGTH) == 0 || parse_json_data(MESSAGE,"previous_blocks_reserve_bytes",data,sizeof(data)) == 0)
    {
      SERVER_RECEIVE_DATA_SOCKET_NETWORK_DATA_NODES_TO_NETWORK_DATA_NODES_DATABASE_SYNC_CHECK_ERROR("Could not parse the message");
    }
  }  

  if (registration_settings == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(block_verifiers_sync_database_list.block_verifiers_public_address[count],public_address,sizeof(public_address)) == 0)
      {
        for (count2 = 0; count2 < DATABASE_TOTAL; count2++)
        {
          memset(block_verifiers_sync_database_list.block_verifiers_database_data_hash[count2][count],0,sizeof(block_verifiers_sync_database_list.block_verifiers_database_data_hash[count2][count]));
          memcpy(block_verifiers_sync_database_list.block_verifiers_database_data_hash[count2][count],data_hash[count2],DATA_HASH_LENGTH);
        }
        block_verifiers_sync_database_list.block_verifiers_previous_block_settings[count] = strncmp(data,"true",BUFFER_SIZE) == 0 ? 1 : 0;
      }
    }
  }
  else
  {
    for (count = 0; count < NETWORK_DATA_NODES_AMOUNT; count++)
    {
      if (strncmp(network_data_nodes_sync_database_list.network_data_node_public_address[count],public_address,sizeof(public_address)) == 0)
      {
        memset(network_data_nodes_sync_database_list.network_data_nodes_database_data_hash[count],0,sizeof(network_data_nodes_sync_database_list.network_data_nodes_database_data_hash[count]));
        memcpy(network_data_nodes_sync_database_list.network_data_nodes_database_data_hash[count],data_hash[0],DATA_HASH_LENGTH);
        network_data_nodes_sync_database_list.network_data_nodes_previous_block_settings[count] = strncmp(data,"true",BUFFER_SIZE) == 0 ? 1 : 0;
      }
    }
  }
  
  return;
  
  #undef SERVER_RECEIVE_DATA_SOCKET_NETWORK_DATA_NODES_TO_NETWORK_DATA_NODES_DATABASE_SYNC_CHECK_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_node_to_block_verifiers_get_reserve_bytes_database_hash
Description: Runs the code when the server receives the NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH message
Parameters:
  CLIENT_SOCKET - The socket to send data to
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_node_to_block_verifiers_get_reserve_bytes_database_hash(const int CLIENT_SOCKET, const char* MESSAGE)
{  

  // TODO rewrite this comple
  // Variables
  char data[BUFFER_SIZE];
  char data2[BUFFER_SIZE];
  char message[BUFFER_SIZE];
  char message2[BUFFER_SIZE];
  size_t count;
  size_t count2;
  size_t current_block_height_reserve_bytes;
  size_t current_block_height_reserve_bytes_copy;
  size_t reserve_bytes_blocks_amount;
  size_t data_size;

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_node_to_block_verifiers_get_reserve_bytes_database_hash",82); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  send_data(CLIENT_SOCKET,(unsigned char*)"Could not get the network blocks reserve bytes database hash}",0,0,""); \
  return;

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(message,0,sizeof(message));
  memset(message2,0,sizeof(message2));
  
  if (strstr(MESSAGE,"|") == NULL && parse_json_data(MESSAGE,"block_height",data,sizeof(data)) == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR("Could not create the message");
  }
  else if (strstr(MESSAGE,"|") != NULL && (string_count(MESSAGE,"|") != GET_RESERVE_BYTES_DATABASE_HASH_PARAMETER_AMOUNT || check_for_invalid_strings(MESSAGE) == 0))
  {
    SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR("Could not create the message");
  }
  else if (strstr(MESSAGE,"|") != NULL)
  {
    for (count = 0, count2 = 0; count < GET_RESERVE_BYTES_DATABASE_HASH_PARAMETER_AMOUNT; count++)
    {
      if (count == 1)
      {
        if ((data_size = strlen(MESSAGE) - strlen(strstr(MESSAGE+count2,"|")) - count2) >= sizeof(data))
        {
          SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR("Invalid message data");
        }
        memcpy(data,&MESSAGE[count2],data_size);
        break;
      }
      count2 = strlen(MESSAGE) - strlen(strstr(MESSAGE+count2,"|")) + 1;
    }
  }

  // check if the block height is valid
  for (count = 0; count < strlen(data); count++)
  {
    if (strncmp(&data[count],"0",1) != 0 && strncmp(&data[count],"1",1) != 0 && strncmp(&data[count],"2",1) != 0 && strncmp(&data[count],"3",1) != 0 && strncmp(&data[count],"4",1) != 0 && strncmp(&data[count],"5",1) != 0 && strncmp(&data[count],"6",1) != 0 && strncmp(&data[count],"7",1) != 0 && strncmp(&data[count],"8",1) != 0 && strncmp(&data[count],"9",1) != 0)
    {
      SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR("Invalid block height}");
    }
  }

  size_t reserve_bytes_index = 0;
  if (get_db_max_block_height(database_name, &count2,&reserve_bytes_index)<0) {
    DEBUG_PRINT("Can't get block height from database");
    send_data(CLIENT_SOCKET,(unsigned char*)"Could not get the network blocks reserve bytes database hash}",0,0,""); \
    return;
  }
  sscanf(data,"%zu",&current_block_height_reserve_bytes);
  current_block_height_reserve_bytes_copy = current_block_height_reserve_bytes;

  // check if the block height is under the XCASH_PROOF_OF_STAKE_BLOCK_HEIGHT or over the current_block_height
  if (test_settings == 0 && (current_block_height_reserve_bytes < XCASH_PROOF_OF_STAKE_BLOCK_HEIGHT || current_block_height_reserve_bytes > count2))
  {
    SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR("Invalid block height");
  }

  // get how many blocks they have requested to sync
  reserve_bytes_blocks_amount = (count2 - current_block_height_reserve_bytes);

  if (reserve_bytes_blocks_amount > BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME)
  {
    // maximum range of blocks returned is 1 days worth of blocks
    reserve_bytes_blocks_amount = BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME;
  }
  if (reserve_bytes_blocks_amount == 0)
  {
    // set it to 1 if 0, due to live syncing it will always show 0
    reserve_bytes_blocks_amount = 1;
  }

  // create the message for the data hash
  for (count = 0; count < reserve_bytes_blocks_amount; count++, current_block_height_reserve_bytes++)
  {
    // create the message
    memset(data,0,strlen(data));
    memset(data2,0,strlen(data2));
    memset(message,0,strlen(message));
    memcpy(data2,"{\"block_height\": \"",18);
    snprintf(data2+18,sizeof(data2)-19,"%zu",current_block_height_reserve_bytes);
    memcpy(data2+strlen(data2),"\"}",2);

    count2 = ((current_block_height_reserve_bytes - XCASH_PROOF_OF_STAKE_BLOCK_HEIGHT) / BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME) + 1;
  
    memcpy(data,"reserve_bytes_",14);
    snprintf(data+14,MAXIMUM_NUMBER_SIZE,"%zu",count2);
    
    // get the data hash
    if (read_document_field_from_collection(database_name,data,data2,"reserve_bytes_data_hash",message) == 0)
    {
      if (strlen(message2) != 0)
      {
          // we have already data to answer
          reserve_bytes_blocks_amount = count; //dirty fix
          break;
      }
      SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR("Could not get the previous blocks reserve bytes");
    }
    memcpy(message2+strlen(message2),message,strnlen(message,sizeof(message2)));
    memcpy(message2+strlen(message2),"|",sizeof(char));
  }

  if (current_block_height_reserve_bytes >= BLOCK_HEIGHT_SF_V_1_2_0)
  {
    // reset the count
    current_block_height_reserve_bytes = current_block_height_reserve_bytes_copy;

    // create the message for the stealth addresses
    for (count = 0; count < reserve_bytes_blocks_amount; count++, current_block_height_reserve_bytes++)
    {
      // create the message
      memset(data,0,strlen(data));
      memset(data2,0,strlen(data2));
      memset(message,0,strlen(message));
      memcpy(data2,"{\"block_height\": \"",18);
      snprintf(data2+18,sizeof(data2)-19,"%zu",current_block_height_reserve_bytes);
      memcpy(data2+strlen(data2),"\"}",2);

      count2 = ((current_block_height_reserve_bytes - XCASH_PROOF_OF_STAKE_BLOCK_HEIGHT) / BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME) + 1;
  
      memcpy(data,"reserve_bytes_",14);
      snprintf(data+14,MAXIMUM_NUMBER_SIZE,"%zu",count2);
    
      // get the reserve bytes
      if (read_document_field_from_collection(database_name,data,data2,"reserve_bytes",message) == 0 || strstr(message,BLOCKCHAIN_STEALTH_ADDRESS_END) == NULL)
      {
        SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR("Could not get the previous blocks reserve bytes");
      }

      // get the stealth address    
      memcpy(message2+strlen(message2),&message[(strlen(message) - strlen(strstr(message,BLOCKCHAIN_STEALTH_ADDRESS_END))) - STEALTH_ADDRESS_OUTPUT_LENGTH],STEALTH_ADDRESS_OUTPUT_LENGTH);
      memcpy(message2+strlen(message2),"|",sizeof(char));
    }
  }
  
  memcpy(message2+strlen(message2),"}",sizeof(char));
  
  // send the data
  test_settings == 0 ? send_data(CLIENT_SOCKET,(unsigned char*)message2,0,0,"") : send_data(CLIENT_SOCKET,(unsigned char*)message2,0,1,"");
  return;
  
  #undef SERVER_RECEIVE_DATA_SOCKET_NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_node_to_block_verifiers_check_if_current_block_verifier
Description: Runs the code when the server receives the NODE_TO_BLOCK_VERIFIERS_CHECK_IF_CURRENT_BLOCK_VERIFIER message
Parameters:
  CLIENT_SOCKET - The socket to send data to
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_node_to_block_verifiers_check_if_current_block_verifier(const int CLIENT_SOCKET)
{  
  // Variables
  char data[10];
  int count;

  log_info("received %s, %s", __func__, "NODE_TO_BLOCK_VERIFIERS_CHECK_IF_CURRENT_BLOCK_VERIFIER");

  memset(data,0,sizeof(data));
  memcpy(data,"0}",2);

  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0)
    {
      memset(data,0,2);
      memcpy(data,"1}",2);
      break;
    }    
  }

  // send the data
  test_settings == 0 ? send_data(CLIENT_SOCKET,(unsigned char*)data,0,0,"") : send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");
  return;
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_proofs_database_sync_check_all_update
Description: Runs the code when the server receives the BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE message
Parameters:
  CLIENT_SOCKET - The socket to send data to
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_proofs_database_sync_check_all_update(const int CLIENT_SOCKET, const char* MESSAGE)
{
  // Variables
  char message[BUFFER_SIZE];
  char reserve_proofs_database[BUFFER_SIZE];
  char data[BUFFER_SIZE];
  char data2[BUFFER_SIZE];
  int count;

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_proofs_database_sync_check_all_update",107); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  ERROR_DATA_MESSAGE;

  memset(message,0,sizeof(message));
  memset(reserve_proofs_database,0,sizeof(reserve_proofs_database));
  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));

  // parse the message
  if (parse_json_data(MESSAGE,"reserve_proofs_data_hash",data,sizeof(data)) == 0 || strlen(data) != DATA_HASH_LENGTH)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not parse the message");
  }

  // disable this part for now, as we need to figure out how to only check reserve proofs that are not empty, otherwise it will give the empty string data hash

  /*// get the database data hash for the reserve proofs database
  if (get_database_data_hash(data2,database_name,"reserve_proofs") == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not get the database data hash for the reserve proofs database");
  }

  // create the message
  if (strncmp(data,data2,DATA_HASH_LENGTH) == 0)
  {
    memcpy(message,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_DOWNLOAD\",\r\n \"reserve_proofs_database\": \"true\",\r\n \"reserve_proofs_database_1\": \"true\",\r\n \"reserve_proofs_database_2\": \"true\",\r\n \"reserve_proofs_database_3\": \"true\",\r\n \"reserve_proofs_database_4\": \"true\",\r\n \"reserve_proofs_database_5\": \"true\",\r\n \"reserve_proofs_database_6\": \"true\",\r\n \"reserve_proofs_database_7\": \"true\",\r\n \"reserve_proofs_database_8\": \"true\",\r\n \"reserve_proofs_database_9\": \"true\",\r\n \"reserve_proofs_database_10\": \"true\",\r\n \"reserve_proofs_database_11\": \"true\",\r\n \"reserve_proofs_database_12\": \"true\",\r\n \"reserve_proofs_database_13\": \"true\",\r\n \"reserve_proofs_database_14\": \"true\",\r\n \"reserve_proofs_database_15\": \"true\",\r\n \"reserve_proofs_database_16\": \"true\",\r\n \"reserve_proofs_database_17\": \"true\",\r\n \"reserve_proofs_database_18\": \"true\",\r\n \"reserve_proofs_database_19\": \"true\",\r\n \"reserve_proofs_database_20\": \"true\",\r\n \"reserve_proofs_database_21\": \"true\",\r\n \"reserve_proofs_database_22\": \"true\",\r\n \"reserve_proofs_database_23\": \"true\",\r\n \"reserve_proofs_database_24\": \"true\",\r\n \"reserve_proofs_database_25\": \"true\",\r\n \"reserve_proofs_database_26\": \"true\",\r\n \"reserve_proofs_database_27\": \"true\",\r\n \"reserve_proofs_database_28\": \"true\",\r\n \"reserve_proofs_database_29\": \"true\",\r\n \"reserve_proofs_database_30\": \"true\",\r\n \"reserve_proofs_database_31\": \"true\",\r\n \"reserve_proofs_database_32\": \"true\",\r\n \"reserve_proofs_database_33\": \"true\",\r\n \"reserve_proofs_database_34\": \"true\",\r\n \"reserve_proofs_database_35\": \"true\",\r\n \"reserve_proofs_database_36\": \"true\",\r\n \"reserve_proofs_database_37\": \"true\",\r\n \"reserve_proofs_database_38\": \"true\",\r\n \"reserve_proofs_database_39\": \"true\",\r\n \"reserve_proofs_database_40\": \"true\",\r\n \"reserve_proofs_database_41\": \"true\",\r\n \"reserve_proofs_database_42\": \"true\",\r\n \"reserve_proofs_database_43\": \"true\",\r\n \"reserve_proofs_database_44\": \"true\",\r\n \"reserve_proofs_database_45\": \"true\",\r\n \"reserve_proofs_database_46\": \"true\",\r\n \"reserve_proofs_database_47\": \"true\",\r\n \"reserve_proofs_database_48\": \"true\",\r\n \"reserve_proofs_database_49\": \"true\",\r\n \"reserve_proofs_database_50\": \"true\",\r\n}",2140);
  }
  else
  {*/
    memcpy(message,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_DOWNLOAD\",\r\n \"reserve_proofs_database\": \"false\",\r\n ",150);
    for (count = 1; count <= TOTAL_RESERVE_PROOFS_DATABASES; count++)
    {
      memcpy(message+strlen(message),"\"reserve_proofs_database_",25);
      snprintf(message+strlen(message),sizeof(message)-1,"%d",count);
      memcpy(message+strlen(message),"\": \"",4);      
      memset(data2,0,strlen(data2));  
      memcpy(data2,"reserve_proofs_data_hash_",25);  
      snprintf(data2+25,sizeof(data2)-26,"%d",count); 
      // parse the message
      if (parse_json_data(MESSAGE,data2,data,sizeof(data)) == 0 || strlen(data) != DATA_HASH_LENGTH)
      {
        SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not parse the message");
      }
      // get the database data hash for the reserve proofs database
      memset(data2,0,strlen(data2));  
      memcpy(data2,"reserve_proofs_",15);  
      snprintf(data2+15,MAXIMUM_NUMBER_SIZE,"%d",count);
      if (get_database_data_hash(reserve_proofs_database,database_name,data2) == 0)
      {
        SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not get the database data hash for the reserve proofs database");
      }
      strncmp(reserve_proofs_database,data,DATA_HASH_LENGTH) == 0 ? memcpy(message+strlen(message),"true",4) : memcpy(message+strlen(message),"false",5);
      memcpy(message+strlen(message),"\",\r\n",4);
    }
    RESET_ERROR_MESSAGES;
    memcpy(message+strlen(message),"}",sizeof(char));
  //}
  
  // sign_data
  if (sign_data(message) == 0)
  { 
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not sign data");
  }

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)message,0,1,"");
  return;
  
  #undef SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_proofs_database_download_file_update
Description: Runs the code when the server receives the BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_UPDATE message
Parameters:
  CLIENT_SOCKET - The socket to send data to
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_proofs_database_download_file_update(const int CLIENT_SOCKET, const char* MESSAGE)
{
  // Variables
  char buffer[1024];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_proofs_database_download_file_update",106); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  ERROR_DATA_MESSAGE;

  memset(buffer,0,sizeof(buffer));

  // parse the message
  if (parse_json_data(MESSAGE,"file",buffer,sizeof(buffer)) == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR("Could not parse the message");
  }

  // get the size of the database and allocate the amount of memory
  const size_t DATABASE_COLLECTION_SIZE = get_database_collection_size(database_name,buffer);

  if (DATABASE_COLLECTION_SIZE == 0)
  {
    ERROR_DATA_MESSAGE;
  }

  char* data;
  char* data2;

  if (time(NULL) > TIME_SF_V_1_0_5_PART_1)
  {
    data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
    data2 = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  }
  else
  {
    data = (char*)calloc(DATABASE_COLLECTION_SIZE+SMALL_BUFFER_SIZE,sizeof(char));
    data2 = (char*)calloc(DATABASE_COLLECTION_SIZE+SMALL_BUFFER_SIZE,sizeof(char));    
  }

  // define macros
  #define pointer_reset_all \
  free(data); \
  data = NULL; \
  free(data2); \
  data2 = NULL;

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || data2 == NULL)
  {
    if (data != NULL)
    {
      pointer_reset(data);
    }
    if (data2 != NULL)
    {
      pointer_reset(data2);
    }
    memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_proofs_database_download_file_update",106);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,buffer);  
    exit(0);
  }

  // get the database data for the reserve proofs database
  if (get_database_data(data2,database_name,buffer) == 0)
  {
    pointer_reset_all;
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR("Could not get the database data hash for the reserve proofs database");
  }

  // create the message
  memcpy(data,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_DOWNLOAD\",\r\n \"reserve_proofs_database\": \"",139);
  memcpy(data+139,data2,strnlen(data2,MAXIMUM_BUFFER_SIZE));
  memcpy(data+strlen(data),"\",\r\n}",5);

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");

  pointer_reset_all;
  return;

  #undef pointer_reset_all
  #undef SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_bytes_database_sync_check_all_update
Description: Runs the code when the server receives the BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE message
Parameters:
  CLIENT_SOCKET - The socket to send data to
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_bytes_database_sync_check_all_update(const int CLIENT_SOCKET, const char* MESSAGE)
{
  // Variables
  char message[BUFFER_SIZE];
  char reserve_bytes_database[BUFFER_SIZE];
  char data[BUFFER_SIZE];
  char data2[BUFFER_SIZE];
  char data3[BUFFER_SIZE];
  size_t count;
  size_t current_reserve_bytes_database;

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_bytes_database_sync_check_all_update",106); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  ERROR_DATA_MESSAGE;

  memset(message,0,sizeof(message));
  memset(reserve_bytes_database,0,sizeof(reserve_bytes_database));
  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));

  // parse the message
  if (parse_json_data(MESSAGE, "reserve_bytes_data_hash", data, sizeof(data)) == 0 ||
      strlen(data) != DATA_HASH_LENGTH ||
      parse_json_data(MESSAGE, "reserve_bytes_settings", data3, sizeof(data3)) == 0 ||
      (strncmp(data3, "0", 1) != 0 && strncmp(data3, "1", 1) != 0)) {
      SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR(
          "Could not parse the message");
  }

  // get the current reserve bytes database
  get_reserve_bytes_database(current_reserve_bytes_database,0);

  // get the database data hash for the reserve bytes database

  if (!get_db_data_hash("reserve_bytes", data2))
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not get the database data hash for the reserve bytes database");

  }
  // if (get_database_data_hash(data2,database_name,"reserve_bytes") == 0)
  // {
  //   SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not get the database data hash for the reserve bytes database");
  // }

  // create the message
  strncmp(data, data2, DATA_HASH_LENGTH) == 0
      ? memcpy(message,
               "{\r\n \"message_settings\": "
               "\"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_DOWNLOAD\",\r\n "
               "\"reserve_bytes_database\": \"true\",\r\n ",
               147)
      : memcpy(message,
               "{\r\n \"message_settings\": "
               "\"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_DOWNLOAD\",\r\n "
               "\"reserve_bytes_database\": \"false\",\r\n ",
               148);

  // check if the block verifier wanted to sync all reserve bytes databases or just the current reserve bytes database
  count = strncmp(data3,"0",1) == 0 ? 1 : current_reserve_bytes_database - 1;
  if (count == 0)
  {
    // set it to only check the current reserve bytes database if their is no previous reserve bytes database
    count = 1;
  }
  
  for (; count <= current_reserve_bytes_database; count++)
  {
    memcpy(message+strlen(message),"\"reserve_bytes_database_",24);
    snprintf(message+strlen(message),sizeof(message)-1,"%zu",count);
    memcpy(message+strlen(message),"\": \"",4);      
    memset(data2,0,strlen(data2));  
    memcpy(data2,"reserve_bytes_data_hash_",24);  
    snprintf(data2+24,sizeof(data2)-25,"%zu",count); 
    // parse the message
    if (parse_json_data(MESSAGE,data2,data,sizeof(data)) == 0 || strlen(data) != DATA_HASH_LENGTH)
    {
      SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not parse the message");
    }
    // get the database data hash for the reserve proofs database
    memset(data2,0,strlen(data2));  
    memcpy(data2,"reserve_bytes_",14);  
    snprintf(data2+14,MAXIMUM_NUMBER_SIZE,"%zu",count);

    if (!get_db_data_hash(data2,reserve_bytes_database))
    {
      SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not get the database data hash for the reserve bytes database");

    }

    strncmp(reserve_bytes_database,data,DATA_HASH_LENGTH) == 0 ? memcpy(message+strlen(message),"true",4) : memcpy(message+strlen(message),"false",5);
    memcpy(message+strlen(message),"\",\r\n",4);
  }
  memcpy(message+strlen(message),"}",sizeof(char));
  
  // sign_data
  if (sign_data(message) == 0)
  { 
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR("Could not sign data");
  }

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)message,0,1,"");
  return;
  
  #undef SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_bytes_database_download_file_update
Description: Runs the code when the server receives the BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_UPDATE message
Parameters:
  CLIENT_SOCKET - The socket to send data to
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_bytes_database_download_file_update(const int CLIENT_SOCKET, const char* MESSAGE)
{
  // Variables
  char buffer[1024];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_bytes_database_download_file_update",105); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  ERROR_DATA_MESSAGE;

  memset(buffer,0,sizeof(buffer));

  // parse the message
  if (parse_json_data(MESSAGE,"file",buffer,sizeof(buffer)) == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR("Could not parse the message");
  }

  // get the size of the database and allocate the amount of memory
  const size_t DATABASE_COLLECTION_SIZE = get_database_collection_size(database_name,buffer);

  if (DATABASE_COLLECTION_SIZE == 0)
  {
    ERROR_DATA_MESSAGE;
  }

  char* data;
  char* data2;

  if (time(NULL) > TIME_SF_V_1_0_5_PART_1)
  {
    data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
    data2 = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  }
  else
  {
    data = (char*)calloc(DATABASE_COLLECTION_SIZE+SMALL_BUFFER_SIZE,sizeof(char));
    data2 = (char*)calloc(DATABASE_COLLECTION_SIZE+SMALL_BUFFER_SIZE,sizeof(char));    
  }
  

  // define macros
  #define pointer_reset_all \
  free(data); \
  data = NULL; \
  free(data2); \
  data2 = NULL;

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || data2 == NULL)
  {
    if (data != NULL)
    {
      pointer_reset(data);
    }
    if (data2 != NULL)
    {
      pointer_reset(data2);
    }
    memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_reserve_bytes_database_download_file_update",105);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,buffer);  
    exit(0);
  }

  // get the database data for the reserve bytes database
  if (get_database_data(data2,database_name,buffer) == 0)
  {
    pointer_reset_all;
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR("Could not get the database data hash for the reserve bytes database");
  }

  // create the message
  memcpy(data,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_DOWNLOAD\",\r\n \"reserve_bytes_database\": \"",137);
  memcpy(data+137,data2,strnlen(data2,MAXIMUM_BUFFER_SIZE));
  memcpy(data+strlen(data),"\",\r\n}",5);

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");

  pointer_reset_all;
  return;

  #undef pointer_reset_all
  #undef SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_block_verifiers_to_block_verifiers_delegates_database_sync_check_update
Description: Runs the code when the server receives the BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_UPDATE message
Parameters:
  CLIENT_SOCKET - The socket to send data to
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_block_verifiers_to_block_verifiers_delegates_database_sync_check_update(const int CLIENT_SOCKET, const char* MESSAGE)
{
  // Variables
  char data[SMALL_BUFFER_SIZE];
  char data2[DATA_HASH_LENGTH+1];

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define DATABASE_COLLECTION "delegates"
  #define SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_UPDATE_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_delegates_database_sync_check_update",98); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  ERROR_DATA_MESSAGE;

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));

  // get the database data hash for the delegates database
  if (get_database_data_hash(data2,database_name,DATABASE_COLLECTION) == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_UPDATE_ERROR("Could not get the database data hash for the delegates database");
  }

  // parse the message
  if (parse_json_data(MESSAGE,"data_hash",data,sizeof(data)) == 0 || strlen(data) != DATA_HASH_LENGTH)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_UPDATE_ERROR("Could not parse the message");
  }

  // create the message
  if (strncmp(data,data2,DATA_HASH_LENGTH) == 0)
  {
    memset(data,0,strlen(data));
    memcpy(data,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_DOWNLOAD\",\r\n \"delegates_database\": \"true\",\r\n}",135);
  }
  else
  {
    memset(data,0,strlen(data));
    memcpy(data,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_DOWNLOAD\",\r\n \"delegates_database\": \"false\",\r\n}",136);
  }
  
  // sign_data
  if (sign_data(data) == 0)
  { 
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_UPDATE_ERROR("Could not sign data");
  }

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");

  return;

  #undef DATABASE_COLLECTION
  #undef SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_UPDATE_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_block_verifiers_to_block_verifiers_delegates_database_download_file_update
Description: Runs the code when the server receives the BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE message
Parameters:
  CLIENT_SOCKET - The socket to send data to
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_block_verifiers_to_block_verifiers_delegates_database_download_file_update(const int CLIENT_SOCKET)
{
  log_info("received %s, %s", __func__, "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE");
  // define macros
  #define DATABASE_COLLECTION "delegates"
  

  // Constants
  const size_t DATABASE_COLLECTION_SIZE = get_database_collection_size(database_name,DATABASE_COLLECTION);

  if (DATABASE_COLLECTION_SIZE == 0)
  {
    ERROR_DATA_MESSAGE;
  }

  char* data;
  char* data2;

  if (time(NULL) > TIME_SF_V_1_0_5_PART_1)
  {
    data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
    data2 = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  }
  else
  {
    data = (char*)calloc(DATABASE_COLLECTION_SIZE+SMALL_BUFFER_SIZE,sizeof(char));
    data2 = (char*)calloc(DATABASE_COLLECTION_SIZE+SMALL_BUFFER_SIZE,sizeof(char));    
  }

  // Variables
  char buffer[1024];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;

  // define macros
  #define pointer_reset_all \
  free(data); \
  data = NULL; \
  free(data2); \
  data2 = NULL;

  #define SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_delegates_database_download_file_update",101); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  pointer_reset_all; \
  ERROR_DATA_MESSAGE;

  memset(buffer,0,sizeof(buffer));

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || data2 == NULL)
  {
    if (data != NULL)
    {
      pointer_reset(data);
    }
    if (data2 != NULL)
    {
      pointer_reset(data2);
    }
    memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_delegates_database_download_file_update",101);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,buffer);  
    exit(0);
  }

  // get the database data for the reserve bytes database
  if (get_database_data(data2,database_name,DATABASE_COLLECTION) == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR("Could not get the database data hash for the delegates database");
  }

  // create the message
  memcpy(data,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_DOWNLOAD\",\r\n \"delegates_database\": \"",129);
  memcpy(data+129,data2,strnlen(data2,MAXIMUM_BUFFER_SIZE));
  memcpy(data+strlen(data),"\",\r\n}",5);

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");

  log_info("answered %s", __func__);



  pointer_reset_all;
  return;

  #undef DATABASE_COLLECTION
  #undef pointer_reset_all
  #undef SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_block_verifiers_to_block_verifiers_statistics_database_sync_check_update
Description: Runs the code when the server receives the BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_UPDATE message
Parameters:
  CLIENT_SOCKET - The socket to send data to
  MESSAGE - The message
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_block_verifiers_to_block_verifiers_statistics_database_sync_check_update(const int CLIENT_SOCKET, const char* MESSAGE)
{
  // Variables
  char data[SMALL_BUFFER_SIZE];
  char data2[DATA_HASH_LENGTH+1];

  log_info("received %s, %s", __func__, MESSAGE);

  // define macros
  #define DATABASE_COLLECTION "statistics"
  #define SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_UPDATE_ERROR(settings) \
  if (debug_settings == 1) \
  { \
  memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_statistics_database_sync_check_update",99); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  } \
  ERROR_DATA_MESSAGE;

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));

  // get the database data hash for the statistics database
  if (get_database_data_hash(data2,database_name,DATABASE_COLLECTION) == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_UPDATE_ERROR("Could not get the database data hash for the statistics database");
  }

  // parse the message
  if (parse_json_data(MESSAGE,"data_hash",data,sizeof(data)) == 0 || strlen(data) != DATA_HASH_LENGTH)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_UPDATE_ERROR("Could not parse the message");
  }

  // create the message
  if (strncmp(data,data2,DATA_HASH_LENGTH) == 0)
  {
    memset(data,0,strlen(data));
    memcpy(data,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_DOWNLOAD\",\r\n \"statistics_database\": \"true\",\r\n}",137);
  }
  else
  {
    memset(data,0,strlen(data));
    memcpy(data,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_DOWNLOAD\",\r\n \"statistics_database\": \"false\",\r\n}",138);
  }
  
  // sign_data
  if (sign_data(data) == 0)
  { 
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_UPDATE_ERROR("Could not sign data");
  }

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");

  return;
  
  #undef SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_UPDATE_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: server_receive_data_socket_block_verifiers_to_block_verifiers_statistics_database_download_file_update
Description: Runs the code when the server receives the BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_UPDATE message
Parameters:
  CLIENT_SOCKET - The socket to send data to
-----------------------------------------------------------------------------------------------------------
*/

void server_receive_data_socket_block_verifiers_to_block_verifiers_statistics_database_download_file_update(const int CLIENT_SOCKET)
{
  // define macros
  #define DATABASE_COLLECTION "statistics"
  
  log_info("received %s, %s", __func__, "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_UPDATE");

  // Constants
  const size_t DATABASE_COLLECTION_SIZE = get_database_collection_size(database_name,DATABASE_COLLECTION);

  if (DATABASE_COLLECTION_SIZE == 0)
  {
    ERROR_DATA_MESSAGE;
  }

  char* data;
  char* data2;

  if (time(NULL) > TIME_SF_V_1_0_5_PART_1)
  {
    data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
    data2 = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  }
  else
  {
    data = (char*)calloc(DATABASE_COLLECTION_SIZE+SMALL_BUFFER_SIZE,sizeof(char));
    data2 = (char*)calloc(DATABASE_COLLECTION_SIZE+SMALL_BUFFER_SIZE,sizeof(char));    
  }

  // Variables
  char buffer[1024];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;

  // define macros
  #define pointer_reset_all \
  free(data); \
  data = NULL; \
  free(data2); \
  data2 = NULL;

  #define SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR(settings) \
  if (debug_settings == 1) \
  { \
    memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_statistics_database_download_file_update",102); \
    memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
    error_message.total++; \
  } \
  pointer_reset_all; \
  ERROR_DATA_MESSAGE;

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || data2 == NULL)
  {
    if (data != NULL)
    {
      pointer_reset(data);
    }
    if (data2 != NULL)
    {
      pointer_reset(data2);
    }
    memcpy(error_message.function[error_message.total],"server_receive_data_socket_block_verifiers_to_block_verifiers_statistics_database_download_file_update",102);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,buffer);  
    exit(0);
  }

  // get the database data for the reserve bytes database
  if (get_database_data(data2,database_name,DATABASE_COLLECTION) == 0)
  {
    SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR("Could not get the database data hash for the statistics database");
  }

  // create the message
  memcpy(data,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_DOWNLOAD\",\r\n \"statistics_database\": \"",131);
  memcpy(data+131,data2,strnlen(data2,MAXIMUM_BUFFER_SIZE));
  memcpy(data+strlen(data),"\",\r\n}",5);

  // send the data
  send_data(CLIENT_SOCKET,(unsigned char*)data,0,1,"");

  pointer_reset_all;
  return;

  #undef DATABASE_COLLECTION
  #undef pointer_reset_all
  #undef SERVER_RECEIVE_DATA_SOCKET_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_UPDATE_ERROR
}

