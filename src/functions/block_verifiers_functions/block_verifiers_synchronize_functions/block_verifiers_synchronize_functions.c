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
#include <errno.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>

#include "define_macro_functions.h"
#include "define_macros.h"
#include "structures.h"
#include "variables.h"
#include "initialize_and_reset_structs_define_macros.h"

#include "blockchain_functions.h"
#include "block_verifiers_synchronize_functions.h"
#include "block_verifiers_thread_server_functions.h"
#include "block_verifiers_update_functions.h"
#include "block_verifiers_functions.h"
#include "database_functions.h"
#include "insert_database_functions.h"
#include "delete_database_functions.h"
#include "count_database_functions.h"
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
#include "xcash_delegates.h"
#include "xcash_db_helpers.h"
#include "xcash_message.h"

/*
-----------------------------------------------------------------------------------------------------------
Functions
-----------------------------------------------------------------------------------------------------------
*/



/// @brief Sync the previous, current and next block verifiers from a network data node. This function is only run at startup, since after that the database is used to get the block verifiers list
/// @param SETTINGS 1 to sync immediately, 0 to wait for the network data nodes to sync
/// @param NETWORK_DATA_NODES_ONLINE_SETTINGS 0 if no network data nodes are online, otherwise 1
/// @return 0 if an error has occurred, 1 if successful
int sync_all_block_verifiers_list(const int SETTINGS, const int NETWORK_DATA_NODES_ONLINE_SETTINGS)
{
  // Variables
  // struct delegates delegates[MAXIMUM_AMOUNT_OF_DELEGATES];
  char message[BUFFER_SIZE];
  char data2[BUFFER_SIZE];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  char data3[BUFFER_SIZE];
  int count;
  int count2;
  size_t total_delegates = 0;
  size_t data_size;

  // define macros
  #define MESSAGE "{\r\n \"message_settings\": \"NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST\",\r\n}"
  #define PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA(settings,block_verifiers_data) \
  memset(data2,0,sizeof(data2)); \
  if (parse_json_data(data3,settings,data2,sizeof(data2)) == 0) \
  { \
    SYNC_ALL_BLOCK_VERIFIERS_LIST_ERROR("Could not parse the message"); \
  } \
  for (count = 0, count2 = 0; count < (int)total_delegates; count++) \
  { \
    if ((data_size = strnlen(data2,sizeof(data2)) - strnlen(strstr(data2+count2,"|"),sizeof(data2)) - count2) >= sizeof(block_verifiers_data)) \
    { \
      SYNC_ALL_BLOCK_VERIFIERS_LIST_ERROR("Invalid message data"); \
    } \
    memcpy((block_verifiers_data)[count],&data2[count2],data_size); \
    count2 = strnlen(data2,sizeof(data2)) - strnlen(strstr(data2+count2,"|"),sizeof(data2)) + 1; \
  }

  #define SYNC_ALL_BLOCK_VERIFIERS_LIST_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"sync_all_block_verifiers_list",29); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  return 0;

  memset(message,0,sizeof(message));
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));


  // reset the previous current and next block verifiers list
  memset(&previous_block_verifiers_list,0,sizeof(previous_block_verifiers_list));
  memset(&current_block_verifiers_list,0,sizeof(current_block_verifiers_list));
  memset(&next_block_verifiers_list,0,sizeof(next_block_verifiers_list));

  if (!is_seed_node && NETWORK_DATA_NODES_ONLINE_SETTINGS == 1)
  {

    // we're a regular delegate node and some of seed nodes are online

    // FIXME: I guess this should done somehow else
    // wait for the network data nodes to load the previous, current and next block verifiers list, before trying to sync them
    if (SETTINGS == 0)
    {
      sleep(10);
    }


    INFO_PRINT("Syncing the previous, current and next block verifiers directly from a network data node, to be able to update the database");
    // if (test_settings == 0)
    // {
    //   print_start_message(current_date_and_time,current_UTC_date_and_time,"Syncing the previous, current and next block verifiers directly from a network data node, to be able to update the database",data2);
    // }

    // create the message

    // char* message_data = create_message(XMSG_NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST);
    // // TODO complete all the things
    // free(message_data);

    // bool loaded_ok = false;
    // while (!loaded_ok) {

    // }    


    start:


    INFO_PRINT("Sending the message to the random seed node to get list of previous, current and next block verifiers");
    // if (test_settings == 0)
    // {
    //   color_print("Connecting to a random network data node to get a list of previous, current and next block verifiers","white");
    // }
    
    memset(data2,0,strlen(data2));
    memset(data3,0,strlen(data3));


    // FIXME Currently it gives any node, offline or online. And didn't store the node we'we already checked
    // send the message to a random network data node
    get_random_network_data_node(count);
  
    // get the current time
    get_current_UTC_time(current_date_and_time,current_UTC_date_and_time);   
    DEBUG_PRINT("Sending NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST to %s", network_data_nodes_list.network_data_nodes_IP_address[count]);
    
    // if (test_settings == 0)
    // {
    //   memcpy(data3,"Connecting to network data node ",32);
    //   memcpy(data3+32,network_data_nodes_list.network_data_nodes_IP_address[count],strnlen(network_data_nodes_list.network_data_nodes_IP_address[count],BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH));
    //   memcpy(data3+strlen(data3)," and sending NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST\n",87);
    //   strftime(data2,sizeof(data2),"%a %d %b %Y %H:%M:%S UTC\n",&current_UTC_date_and_time);
    //   memcpy(data3+strlen(data3),data2,strnlen(data2,sizeof(data3)));
    //   color_print(data3,"white");
    // }
    memset(data2,0,strlen(data2));
    memset(data3,0,strlen(data3));

    if (send_and_receive_data_socket(data3,sizeof(data3),network_data_nodes_list.network_data_nodes_IP_address[count],SEND_DATA_PORT,message,SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS) == 0)
    {
      memset(data2,0,strlen(data2));
      memcpy(data2,"Could not receive data from network data node ",46);
      memcpy(data2+46,network_data_nodes_list.network_data_nodes_IP_address[count],strnlen(network_data_nodes_list.network_data_nodes_IP_address[count],BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH));
      color_print(data2,"red");
      color_print("Connecting to a different network data node\n","white");
      goto start;
    }

    if (verify_data(data3,0) == 0)
    {
      SYNC_ALL_BLOCK_VERIFIERS_LIST_ERROR("Could not verify data");
    }

    total_delegates = (int)(string_count(data3,"|") / 12);
    
    // FIXME that crazyness
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("previous_block_verifiers_name_list",previous_block_verifiers_list.block_verifiers_name);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("previous_block_verifiers_public_address_list",previous_block_verifiers_list.block_verifiers_public_address);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("previous_block_verifiers_public_key_list",previous_block_verifiers_list.block_verifiers_public_key);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("previous_block_verifiers_IP_address_list",previous_block_verifiers_list.block_verifiers_IP_address);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("current_block_verifiers_name_list",current_block_verifiers_list.block_verifiers_name);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("current_block_verifiers_public_address_list",current_block_verifiers_list.block_verifiers_public_address);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("current_block_verifiers_public_key_list",current_block_verifiers_list.block_verifiers_public_key);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("current_block_verifiers_IP_address_list",current_block_verifiers_list.block_verifiers_IP_address);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("next_block_verifiers_name_list",next_block_verifiers_list.block_verifiers_name);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("next_block_verifiers_public_address_list",next_block_verifiers_list.block_verifiers_public_address);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("next_block_verifiers_public_key_list",next_block_verifiers_list.block_verifiers_public_key);
    PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA("next_block_verifiers_IP_address_list",next_block_verifiers_list.block_verifiers_IP_address);
    if (test_settings == 0)
    {
      color_print("The previous, current and next block verifiers have been synced from a network data node","green");
    }
  }
  else
  {
    // seeds are offline
    // whoever we're we need to load from the local delegates db
    INFO_PRINT("Loading the previous, current and next block verifiers from the database");

    // initialize the delegates struct
    delegates_t* delegates = (delegates_t*)calloc(MAXIMUM_AMOUNT_OF_DELEGATES, sizeof(delegates_t));

    if (read_organize_delegates(delegates, &total_delegates) != XCASH_OK) {
      ERROR_PRINT("Could not organize the delegates");

      free(delegates);
      return XCASH_ERROR;
    }

    total_delegates = total_delegates > BLOCK_VERIFIERS_TOTAL_AMOUNT ? BLOCK_VERIFIERS_TOTAL_AMOUNT: total_delegates;

    // FIXME: that's a shitty code
    // copy the delegates to the next, current and previous block verifiers list
    for (count = 0; count < (int)total_delegates; count++)
    {
      memcpy(previous_block_verifiers_list.block_verifiers_name[count],delegates[count].delegate_name,strnlen(delegates[count].delegate_name,sizeof(previous_block_verifiers_list.block_verifiers_name[count])));
      memcpy(previous_block_verifiers_list.block_verifiers_public_address[count],delegates[count].public_address,strnlen(delegates[count].public_address,sizeof(previous_block_verifiers_list.block_verifiers_public_address[count])));
      memcpy(previous_block_verifiers_list.block_verifiers_public_key[count],delegates[count].public_key,strnlen(delegates[count].public_key,sizeof(previous_block_verifiers_list.block_verifiers_public_key[count])));
      memcpy(previous_block_verifiers_list.block_verifiers_IP_address[count],delegates[count].IP_address,strnlen(delegates[count].IP_address,sizeof(previous_block_verifiers_list.block_verifiers_IP_address[count])));
      memcpy(current_block_verifiers_list.block_verifiers_name[count],delegates[count].delegate_name,strnlen(delegates[count].delegate_name,sizeof(current_block_verifiers_list.block_verifiers_name[count])));
      memcpy(current_block_verifiers_list.block_verifiers_public_address[count],delegates[count].public_address,strnlen(delegates[count].public_address,sizeof(current_block_verifiers_list.block_verifiers_public_address[count])));
      memcpy(current_block_verifiers_list.block_verifiers_public_key[count],delegates[count].public_key,strnlen(delegates[count].public_key,sizeof(current_block_verifiers_list.block_verifiers_public_key[count])));
      memcpy(current_block_verifiers_list.block_verifiers_IP_address[count],delegates[count].IP_address,strnlen(delegates[count].IP_address,sizeof(current_block_verifiers_list.block_verifiers_IP_address[count])));
      memcpy(next_block_verifiers_list.block_verifiers_name[count],delegates[count].delegate_name,strnlen(delegates[count].delegate_name,sizeof(next_block_verifiers_list.block_verifiers_name[count])));
      memcpy(next_block_verifiers_list.block_verifiers_public_address[count],delegates[count].public_address,strnlen(delegates[count].public_address,sizeof(next_block_verifiers_list.block_verifiers_public_address[count])));
      memcpy(next_block_verifiers_list.block_verifiers_public_key[count],delegates[count].public_key,strnlen(delegates[count].public_key,sizeof(next_block_verifiers_list.block_verifiers_public_key[count])));
      memcpy(next_block_verifiers_list.block_verifiers_IP_address[count],delegates[count].IP_address,strnlen(delegates[count].IP_address,sizeof(next_block_verifiers_list.block_verifiers_IP_address[count])));
    }

    INFO_PRINT("The previous, current and next block verifiers have been loaded from the database");

    // cleanup the allocated memory
    free(delegates);
  }

  return XCASH_OK;
  
  #undef MESSAGE
  #undef PARSE_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST_DATA
  #undef SYNC_ALL_BLOCK_VERIFIERS_LIST_ERROR  
}



/*
-----------------------------------------------------------------------------------------------------------
Name: get_synced_block_verifiers
Description: Gets the synced block verifiers for syncing the database
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int get_synced_block_verifiers(void)
{
  // Variables
  char data[BUFFER_SIZE];
  char data2[BUFFER_SIZE];
  char message[SMALL_BUFFER_SIZE];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  int count;
  int count2;
  size_t total_delegates = 0;
  size_t data_size;

  // define macros
  #define MESSAGE "{\r\n \"message_settings\": \"NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST\",\r\n}"

  #define PARSE_BLOCK_VERIFIERS_LIST_DATA(settings,block_verifiers_data) \
  memset(data,0,sizeof(data)); \
  if (parse_json_data(data2,settings,data,sizeof(data)) == 0) \
  { \
    GET_SYNCED_BLOCK_VERIFIERS_ERROR("Could not parse the message"); \
  } \
  for (count = 0, count2 = 0; count < (int)total_delegates; count++) \
  { \
    if ((data_size = strnlen(data,sizeof(data)) - strnlen(strstr(data+count2,"|"),sizeof(data)) - count2) >= sizeof(block_verifiers_data[count])) \
    { \
      GET_SYNCED_BLOCK_VERIFIERS_ERROR("Invalid message data"); \
    } \
    memcpy(block_verifiers_data[count],&data[count2],data_size); \
    count2 = strnlen(data,sizeof(data)) - strnlen(strstr(data+count2,"|"),sizeof(data)) + 1; \
  }

  #define GET_SYNCED_BLOCK_VERIFIERS_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"get_synced_block_verifiers",26); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  return 0;

  // reset the synced_block_verifiers
  for (count = 0; count < BLOCK_VERIFIERS_TOTAL_AMOUNT; count++)
  {
    memset(synced_block_verifiers.synced_block_verifiers_public_address[count],0,sizeof(synced_block_verifiers.synced_block_verifiers_public_address[count]));
    memset(synced_block_verifiers.synced_block_verifiers_public_key[count],0,sizeof(synced_block_verifiers.synced_block_verifiers_public_key[count]));
    memset(synced_block_verifiers.synced_block_verifiers_IP_address[count],0,sizeof(synced_block_verifiers.synced_block_verifiers_IP_address[count]));
    memset(synced_block_verifiers.vote_settings[count],0,sizeof(synced_block_verifiers.vote_settings[count]));
  }
  synced_block_verifiers.vote_settings_true = 0;
  synced_block_verifiers.vote_settings_false = 0;
  synced_block_verifiers.vote_settings_connection_timeout = 0;

  start:
  if (test_settings == 0)
  {
    color_print("Connecting to a random network data node to get a list of current block verifiers","white");
  }

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(message,0,sizeof(message));

  // create the message
  memcpy(message,MESSAGE,sizeof(MESSAGE)-1);

  // sign the data
  if (sign_data(message) == 0)
  {
    GET_SYNCED_BLOCK_VERIFIERS_ERROR("Could not sign data");
  }
  
  // send the message to a random network data node
  get_random_network_data_node(count);
  
  // get the current time
  get_current_UTC_time(current_date_and_time,current_UTC_date_and_time);
  
  if (test_settings == 0)
  {
    memcpy(data,"Connecting to network data node ",32);
    memcpy(data+32,network_data_nodes_list.network_data_nodes_IP_address[count],strnlen(network_data_nodes_list.network_data_nodes_IP_address[count],BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH));
    memcpy(data+strlen(data)," and sending NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST\n",73);
    strftime(data2,sizeof(data2),"%a %d %b %Y %H:%M:%S UTC\n",&current_UTC_date_and_time);
    memcpy(data+strlen(data),data2,strnlen(data2,sizeof(data)));
    color_print(data,"white");
  }
  memset(data,0,strlen(data));
  memset(data2,0,strlen(data2));

  if (send_and_receive_data_socket(data2,sizeof(data2),network_data_nodes_list.network_data_nodes_IP_address[count],SEND_DATA_PORT,message,SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS) == 0)
  {
    memcpy(data,"Could not receive data from network data node ",46);
    memcpy(data+46,network_data_nodes_list.network_data_nodes_IP_address[count],strnlen(network_data_nodes_list.network_data_nodes_IP_address[count],BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH));
    color_print(data,"red");
    memset(data,0,sizeof(data));
    color_print("Connecting to a different network data node\n","white");
    goto start;
  }

  if (verify_data(data2,0) == 0)
  {
    GET_SYNCED_BLOCK_VERIFIERS_ERROR("Could not verify data");
  }

  // get the delegate amount
  total_delegates = (int)(string_count(data2,"|") / 3);

  PARSE_BLOCK_VERIFIERS_LIST_DATA("block_verifiers_public_address_list",synced_block_verifiers.synced_block_verifiers_public_address);
  PARSE_BLOCK_VERIFIERS_LIST_DATA("block_verifiers_public_key_list",synced_block_verifiers.synced_block_verifiers_public_key);
  PARSE_BLOCK_VERIFIERS_LIST_DATA("block_verifiers_IP_address_list",synced_block_verifiers.synced_block_verifiers_IP_address);
  synced_block_verifiers.last_refresh_time_of_synced_block_verifiers = time(NULL);
  
  return 1;

  #undef MESSAGE
  #undef PARSE_BLOCK_VERIFIERS_LIST_DATA
  #undef GET_SYNCED_BLOCK_VERIFIERS_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: get_block_verifier_for_syncing_database
Description: Gets a block verifier for syncing the database from
Paramters:
  settings - 1 to sync from a random block verifier, 2 to sync from a random network data node, otherwise the index of the network data node to sync from + 3
  DELEGATES_IP_ADDRESS - The specific delegates IP address, if you are syncing directly from a delegate, otherwise an empty string
  block_verifiers_ip_address - The selected block verifier to sync the database from
  DATABASE_SETTINGS - The database count
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

void get_block_verifier_for_syncing_database(int settings, const char* DELEGATES_IP_ADDRESS, char *block_verifiers_ip_address, const int DATABASE_SETTINGS)
{
  // Variables
  int count;
  
  if (strncmp(DELEGATES_IP_ADDRESS,"",1) == 0)
  {
    /* select a random block verifier from the majority vote settings to sync the database from, making sure not to select your own block verifier node
       select a random network data node to sync from if there was a lot of connection_timeouts, to where a majority vote could not be calculated, there were more than BLOCK_VERIFIERS_AMOUNT - BLOCK_VERIFIERS_VALID_AMOUNT new block verifiers
    */
    
    if (settings == 1)
    {
      do
      {
        count = (rand() % BLOCK_VERIFIERS_AMOUNT);
      } while (strncmp(synced_block_verifiers.vote_settings[count],"true",4) == 0 || strncmp(synced_block_verifiers.synced_block_verifiers_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0);
      memcpy(block_verifiers_ip_address,synced_block_verifiers.synced_block_verifiers_IP_address[count],strnlen(synced_block_verifiers.synced_block_verifiers_IP_address[count],sizeof(synced_block_verifiers.synced_block_verifiers_IP_address[count])));
    }
    else if (settings == 2)
    {
      get_random_network_data_node(count);
      memcpy(block_verifiers_ip_address,network_data_nodes_list.network_data_nodes_IP_address[count],strnlen(network_data_nodes_list.network_data_nodes_IP_address[count],sizeof(network_data_nodes_list.network_data_nodes_IP_address[count])));
    }
    else
    {     
      memcpy(block_verifiers_ip_address,network_data_nodes_list.network_data_nodes_IP_address[settings-3],strnlen(network_data_nodes_list.network_data_nodes_IP_address[settings-3],sizeof(network_data_nodes_list.network_data_nodes_IP_address[settings-3])));
    }
  }
  else
  {
    if (strncmp(DELEGATES_IP_ADDRESS,SYNCED_BLOCK_VERIFIER_STRING,BUFFER_SIZE) == 0)
    {
      // get a random block verifier that is a synced block verifier
      do
      {
        count = ((rand() % BLOCK_VERIFIERS_AMOUNT));
      } while (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0 || synced_block_verifiers_nodes[DATABASE_SETTINGS][count] == -1);
      memcpy(block_verifiers_ip_address,current_block_verifiers_list.block_verifiers_IP_address[count],strnlen(current_block_verifiers_list.block_verifiers_IP_address[count],BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH));
    }
    else if (strncmp(DELEGATES_IP_ADDRESS,SYNCED_NETWORK_DATA_NODES_STRING,BUFFER_SIZE) == 0)
    {
      // get a random network data node that is a synced network data node
      do
      {
        count = ((rand() % NETWORK_DATA_NODES_AMOUNT));
      } while (strncmp(network_data_nodes_list.network_data_nodes_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0 || synced_network_data_nodes[count] == -1);
      memcpy(block_verifiers_ip_address,network_data_nodes_list.network_data_nodes_IP_address[count],strnlen(network_data_nodes_list.network_data_nodes_IP_address[count],BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH));
    }
    else
    {
      memcpy(block_verifiers_ip_address,DELEGATES_IP_ADDRESS,strnlen(DELEGATES_IP_ADDRESS,BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH));
    }
  }
  return;
}



/*
-----------------------------------------------------------------------------------------------------------
Name: sync_check_reserve_proofs_specific_database
Description: Checks if all of the specific reserve proofs databases need to be synced and syncs them if needed
Paramters:
  DATABASE_DATA - The database data
  block_verifiers_ip_address - The selected block verifier to sync the database from
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int sync_check_reserve_proofs_specific_database(const char* DATABASE_DATA, const char* BLOCK_VERIFIERS_IP_ADDRESS)
{
  // Variables
  char* data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  char data2[SMALL_BUFFER_SIZE];
  char* data3 = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  int count;
  
  // define macros
  #define pointer_reset_all \
  free(data); \
  data = NULL; \
  free(data3); \
  data3 = NULL;

  #define SYNC_CHECK_RESERVE_PROOFS_SPECIFIC_DATABASE_ERROR(message) \
  memcpy(error_message.function[error_message.total],"sync_check_reserve_proofs_specific_database",43); \
  memcpy(error_message.data[error_message.total],message,strnlen(message,BUFFER_SIZE)); \
  error_message.total++; \
  pointer_reset_all; \
  return 0;

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || data3 == NULL)
  {
    if (data != NULL)
    {
      pointer_reset(data);
    }  
    if (data3 != NULL)
    {
      pointer_reset(data3);
    }  
    memcpy(error_message.function[error_message.total],"sync_check_reserve_proofs_specific_database",43);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,data2);  
    exit(0);
  }

  memset(data2,0,sizeof(data2));

  for (count = 1; count <= TOTAL_RESERVE_PROOFS_DATABASES; count++)
  {
    // parse the database_data
    memset(data,0,strlen(data));
    memset(data2,0,strlen(data2));
    memset(data3,0,strlen(data3));
    memcpy(data2,"reserve_proofs_database_",24);
    snprintf(data2+24,sizeof(data2)-25,"%d",count);

    if (parse_json_data(DATABASE_DATA,data2,data,MAXIMUM_BUFFER_SIZE) == 0)
    {
      SYNC_CHECK_RESERVE_PROOFS_SPECIFIC_DATABASE_ERROR("Could not receive data from the block verifier");
    }
   
    if (strncmp(data,"false",5) == 0)
    {
      // sync the database
      if (test_settings == 0)
      {
        memset(data,0,strlen(data));
        memcpy(data,"reserve_proofs_",15);
        snprintf(data+strlen(data),MAXIMUM_BUFFER_SIZE-1,"%d",count);
        memcpy(data+strlen(data)," is not synced, downloading it from ",36);
        memcpy(data+strlen(data),BLOCK_VERIFIERS_IP_ADDRESS,strnlen(BLOCK_VERIFIERS_IP_ADDRESS,MAXIMUM_BUFFER_SIZE));
        color_print(data,"red");
      }

      // create the message
      memset(data2,0,sizeof(data2));
      memcpy(data2,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_UPDATE\",\r\n \"file\": \"reserve_proofs_",133);
      snprintf(data2+133,sizeof(data2)-134,"%d",count);
      memcpy(data2+strlen(data2),"\",\r\n}",5);

      // sign_data
      if (sign_data(data2) == 0)
      { 
        SYNC_CHECK_RESERVE_PROOFS_SPECIFIC_DATABASE_ERROR("Could not sign_data");
      }     
      memset(data,0,strlen(data));

      // allow the database data to be received over the socket
      database_data_socket_settings = 1;

      if (send_and_receive_data_socket(data,MAXIMUM_BUFFER_SIZE,BLOCK_VERIFIERS_IP_ADDRESS,SEND_DATA_PORT,data2,DATABASE_SYNCING_TIMEOUT_SETTINGS) == 0)
      {
        database_data_socket_settings = 0;
        SYNC_CHECK_RESERVE_PROOFS_SPECIFIC_DATABASE_ERROR("Could not receive data from the block verifier");
      }
      database_data_socket_settings = 0;

      // parse the message
      memset(data3,0,strlen(data3));
      if (parse_json_data(data,"reserve_proofs_database",data3,MAXIMUM_BUFFER_SIZE) == 0)
      {
        SYNC_CHECK_RESERVE_PROOFS_SPECIFIC_DATABASE_ERROR("Could not receive data from the block verifier");
      }

      // add the data to the database
      memset(data2,0,strlen(data2));
      memcpy(data2,"reserve_proofs_",15);
      snprintf(data2+15,MAXIMUM_NUMBER_SIZE,"%d",count);

      // FIXME we can't delete the database it caused problems

      // // delete the collection from the database
      // delete_collection_from_database(database_name,data2);

      // if the database is empty dont add any data
      if (strncmp(data3,DATABASE_EMPTY_STRING,BUFFER_SIZE) != 0)
      {
        // add the data to the database
        memset(data,0,strlen(data));
        memcpy(data,data3,strlen(data3)-2);
        insert_multiple_documents_into_collection_json(database_name,data2,data,MAXIMUM_BUFFER_SIZE);
        //data3[strlen(data3)-2] = 0;
        //insert_multiple_documents_into_collection_json(database_name,data2,data3,MAXIMUM_BUFFER_SIZE);
      }     

      memset(data,0,strlen(data));
      memcpy(data,"reserve_proofs_",15);
      snprintf(data+strlen(data),MAXIMUM_BUFFER_SIZE-1,"%d",count);
      memcpy(data+strlen(data)," has been synced successfully\n",31);
      color_print(data,"green");
    }
  }

  pointer_reset_all;
  return 1;

  #undef pointer_reset_all  
  #undef SYNC_CHECK_RESERVE_PROOFS_SPECIFIC_DATABASE_ERROR   
}



/*
-----------------------------------------------------------------------------------------------------------
Name: sync_check_reserve_bytes_specific_database
Description: Checks if all of the specific reserve bytes databases need to be synced and syncs them if needed
Paramters:
  DATABASE_DATA - The database data
  block_verifiers_ip_address - The selected block verifier to sync the database from
  starting_reserve_bytes_database - The starting reserve bytes database
  CURRENT_RESERVE_BYTES_DATABASE - The current reserve bytes database
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int sync_check_reserve_bytes_specific_database(const char* DATABASE_DATA, const char* BLOCK_VERIFIERS_IP_ADDRESS, size_t starting_reserve_bytes_database, const size_t CURRENT_RESERVE_BYTES_DATABASE)
{
  // Variables
  char* data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  char data2[BUFFER_SIZE];
  char* data3 = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  
  // define macros
  #define pointer_reset_all \
  free(data); \
  data = NULL; \
  free(data3); \
  data3 = NULL; \

  #define SYNC_CHECK_RESERVE_BYTES_SPECIFIC_DATABASE_ERROR(message) \
  memcpy(error_message.function[error_message.total],"sync_check_reserve_bytes_specific_database",42); \
  memcpy(error_message.data[error_message.total],message,strnlen(message,BUFFER_SIZE)); \
  error_message.total++; \
  pointer_reset_all; \
  return 0;

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || data3 == NULL)
  {
    if (data != NULL)
    {
      pointer_reset(data);
    }  
    if (data3 != NULL)
    {
      pointer_reset(data3);
    }  
    memcpy(error_message.function[error_message.total],"sync_check_reserve_bytes_specific_database",42);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,data2);  
    exit(0);
  }

  memset(data2,0,sizeof(data2));

  for (; starting_reserve_bytes_database <= CURRENT_RESERVE_BYTES_DATABASE; starting_reserve_bytes_database++)
  {
    if (test_settings == 0)
    {
      memset(data,0,strlen(data));
      memcpy(data,"Checking if reserve_bytes_",26);
      snprintf(data+strlen(data),MAXIMUM_BUFFER_SIZE-1,"%zu",starting_reserve_bytes_database);
      memcpy(data+strlen(data)," is synced",10);
      color_print(data,"white");
    }

    // parse the database_data
    memset(data,0,strlen(data));
    memset(data2,0,sizeof(data2));
    memset(data3,0,strlen(data3));
    memcpy(data2,"reserve_bytes_database_",23);
    snprintf(data2+23,sizeof(data2)-24,"%zu",starting_reserve_bytes_database);

    if (parse_json_data(DATABASE_DATA,data2,data,MAXIMUM_BUFFER_SIZE) == 0)
    {
      SYNC_CHECK_RESERVE_BYTES_SPECIFIC_DATABASE_ERROR("Could not receive data from the block verifier");
    }
   
    if (strncmp(data,"false",5) == 0)
    {
      if (test_settings == 0)
      {
        // sync the database
        memset(data,0,strlen(data));
        memcpy(data,"reserve_bytes_",14);
        snprintf(data+strlen(data),MAXIMUM_BUFFER_SIZE-1,"%zu",starting_reserve_bytes_database);
        memcpy(data+strlen(data)," is not synced, downloading it from ",36);
        memcpy(data+strlen(data),BLOCK_VERIFIERS_IP_ADDRESS,strnlen(BLOCK_VERIFIERS_IP_ADDRESS,MAXIMUM_BUFFER_SIZE));
        color_print(data,"red");
      }

      // create the message
      memset(data2,0,strlen(data2));
      memcpy(data2,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_UPDATE\",\r\n \"file\": \"reserve_bytes_",131);
      snprintf(data2+131,sizeof(data2)-132,"%zu",starting_reserve_bytes_database);
      memcpy(data2+strlen(data2),"\",\r\n}",5);

      // sign_data
      if (sign_data(data2) == 0)
      { 
        SYNC_CHECK_RESERVE_BYTES_SPECIFIC_DATABASE_ERROR("Could not sign_data");
      }     
      memset(data,0,strlen(data));

      // allow the database data to be received over the socket
      database_data_socket_settings = 1;

      if (send_and_receive_data_socket(data,MAXIMUM_BUFFER_SIZE,BLOCK_VERIFIERS_IP_ADDRESS,SEND_DATA_PORT,data2,DATABASE_SYNCING_TIMEOUT_SETTINGS) == 0)
      {
        database_data_socket_settings = 0;
        SYNC_CHECK_RESERVE_BYTES_SPECIFIC_DATABASE_ERROR("Could not receive data from the block verifier3");
      }
      database_data_socket_settings = 0;

      // parse the message
      memset(data3,0,strlen(data3));
      if (parse_json_data(data,"reserve_bytes_database",data3,MAXIMUM_BUFFER_SIZE) == 0)
      {
        SYNC_CHECK_RESERVE_BYTES_SPECIFIC_DATABASE_ERROR("Could not receive data from the block verifier1");
      }

      // add the data to the database
      memset(data2,0,strlen(data2));
      memcpy(data2,"reserve_bytes_",14);
      snprintf(data2+14,MAXIMUM_NUMBER_SIZE,"%zu",starting_reserve_bytes_database);

      // FIXME we can't delete the database it caused problems

      // // delete the collection from the database
      // delete_collection_from_database(database_name,data2);

      // if the database is empty dont add any data
      if (strncmp(data3,DATABASE_EMPTY_STRING,BUFFER_SIZE) != 0)
      {
        // add the data to the database
        memset(data,0,strlen(data));
        memcpy(data,data3,strlen(data3)-2);
        insert_multiple_documents_into_collection_json(database_name,data2,data,MAXIMUM_BUFFER_SIZE);
        //data3[strlen(data3)-2] = 0;
        //insert_multiple_documents_into_collection_json(database_name,data2,data3,MAXIMUM_BUFFER_SIZE);
      }      

      memset(data,0,strlen(data));
      memcpy(data,"reserve_bytes_",14);
      snprintf(data+strlen(data),MAXIMUM_BUFFER_SIZE-1,"%zu",starting_reserve_bytes_database);
      memcpy(data+strlen(data)," has been synced successfully\n",31);
    }
    else
    {
      if (test_settings == 0)
      {
        memset(data,0,strlen(data));
        memcpy(data,"reserve_bytes_",14);
        snprintf(data+strlen(data),MAXIMUM_BUFFER_SIZE-1,"%zu",starting_reserve_bytes_database);
        memcpy(data+strlen(data)," is already synced\n",19);
      }
    }
  }

  pointer_reset_all;
  return 1;

  #undef pointer_reset_all  
  #undef SYNC_CHECK_RESERVE_BYTES_SPECIFIC_DATABASE_ERROR   
}



/*
-----------------------------------------------------------------------------------------------------------
Name: sync_reserve_proofs_database
Description: Syncs the reserve proofs database
Paramters:
  settings - 1 to sync from a random block verifier, 2 to sync from a random network data node, otherwise the index of the network data node to sync from + 3
  DELEGATES_IP_ADDRESS - The specific delegates IP address, if you are syncing directly from a delegate, or if it is SYNCED_BLOCK_VERIFIER_STRING then it will sync from a random synced block verifier, otherwise an empty string
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int sync_reserve_proofs_database(int settings, const char* DELEGATES_IP_ADDRESS)
{
  // Variables
  char data[BUFFER_SIZE];
  char data2[BUFFER_SIZE];
  char data3[BUFFER_SIZE];
  char database_data[BUFFER_SIZE];
  char block_verifiers_ip_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH];
  int count;
  int reset_count = 1;
  
  // define macros
  #define SYNC_RESERVE_PROOFS_DATABASE_ERROR(message) \
  memset(data,0,strlen(data)); \
  memcpy(data+strlen(data),message,strnlen(message,BUFFER_SIZE)); \
  memcpy(data+strlen(data),block_verifiers_ip_address,strnlen(block_verifiers_ip_address,BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH)); \
  memcpy(data+strlen(data),"\nConnecting to another block verifier",37); \
  color_print(data,"red"); \
  if (reset_count >= MAXIMUM_DATABASE_SYNC_CONNECTIONS_ATTEMPTS) \
  { \
    exit(0); \
  } \
  else \
  { \
    reset_count++; \
    goto start; \
  }

  start:

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));
  memset(database_data,0,sizeof(database_data));
  memset(block_verifiers_ip_address,0,sizeof(block_verifiers_ip_address));

  // get a block verifier to sync the database from
  get_block_verifier_for_syncing_database(settings,DELEGATES_IP_ADDRESS,block_verifiers_ip_address,0);

  // get the database data hash for the reserve proofs database
  if (test_settings == 0)
  {
    memset(data3,0,strlen(data3));
    memcpy(data3,"Getting the database data from ",31);
    memcpy(data3+31,block_verifiers_ip_address,strnlen(block_verifiers_ip_address,sizeof(block_verifiers_ip_address)));
    memcpy(data3+strlen(data3),"\n",sizeof(char));
    color_print(data3,"white");
  }
  if (get_database_data_hash(data,database_name,"reserve_proofs") == 0)
  {
    SYNC_RESERVE_PROOFS_DATABASE_ERROR("Could not get the database data hash for the reserve proofs database from ");
  }

  // create the message
  memset(data3,0,strlen(data3));
  memcpy(data3,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE\",\r\n \"reserve_proofs_data_hash\": \"",139);
  memcpy(data3+strlen(data3),data,DATA_HASH_LENGTH);
  memcpy(data3+strlen(data3),"\",\r\n ",5);

  for (count = 1; count <= TOTAL_RESERVE_PROOFS_DATABASES; count++)
  {
    memcpy(data3+strlen(data3),"\"reserve_proofs_data_hash_",26);
    snprintf(data3+strlen(data3),sizeof(data3)-2,"%d",count);
    memcpy(data3+strlen(data3),"\": \"",4);
    // get the database data hash for the reserve proofs database
    memset(data,0,strlen(data));
    memset(data2,0,strlen(data2));  
    memcpy(data2,"reserve_proofs_",15);  
    snprintf(data2+15,MAXIMUM_NUMBER_SIZE,"%d",count);
    if (get_database_data_hash(data,database_name,data2) == 0)
    {
      SYNC_RESERVE_PROOFS_DATABASE_ERROR("Could not get the database data hash for the reserve proofs database from ");
    }
    memcpy(data3+strlen(data3),data,DATA_HASH_LENGTH);
    memcpy(data3+strlen(data3),"\",\r\n ",5);
  }
  memcpy(data3+strlen(data3),"}",sizeof(char));

  // sign_data
  if (sign_data(data3) == 0)
  { 
    SYNC_RESERVE_PROOFS_DATABASE_ERROR("Could not sign_data");
  }

  // connect to the block verifier and get the database data
  if (send_and_receive_data_socket(database_data,sizeof(database_data),block_verifiers_ip_address,SEND_DATA_PORT,data3,DATABASE_SYNCING_TIMEOUT_SETTINGS) == 0)
  {
    SYNC_RESERVE_PROOFS_DATABASE_ERROR("Could not receive data from ");
  }

  if (verify_data(database_data,0) == 0)
  {
    SYNC_RESERVE_PROOFS_DATABASE_ERROR("Could not verify data from ");
  }

  // check if the block verifier needs to sync any of the reserve proof databases and sync them if needed
  if (sync_check_reserve_proofs_specific_database(database_data,(const char*)block_verifiers_ip_address) == 0)
  {
    SYNC_RESERVE_PROOFS_DATABASE_ERROR("Could not check if any of the specific databases needed to be synced, from ");
  }

  return 1;

  #undef SYNC_RESERVE_PROOFS_DATABASE_ERROR   
}



/*
-----------------------------------------------------------------------------------------------------------
Name: sync_reserve_bytes_database
Description: Syncs the reserve bytes database
Paramters:
  settings - 1 to sync from a random block verifier, 2 to sync from a random network data node, otherwise the index of the network data node to sync from + 3
  RESERVE_BYTES_START_SETTINGS - 0 to sync all of the reserve bytes databases, 1 to only sync the current reserve bytes database
  DELEGATES_IP_ADDRESS - The specific delegates IP address, if you are syncing directly from a delegate, otherwise an empty string
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int sync_reserve_bytes_database(int settings, const int RESERVE_BYTES_START_SETTINGS, const char* DELEGATES_IP_ADDRESS)
{
  // Variables
  char data[BUFFER_SIZE];
  char data2[BUFFER_SIZE];
  char data3[BUFFER_SIZE];
  char database_data[BUFFER_SIZE];
  char block_verifiers_ip_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH];
  size_t count;
  size_t count2;
  size_t current_reserve_bytes_database;
  int reset_count = 1;
  
  // define macros
  #define SYNC_RESERVE_BYTES_DATABASE_ERROR(message) \
  memset(data,0,strlen(data)); \
  memcpy(data+strlen(data),message,strnlen(message,BUFFER_SIZE)); \
  memcpy(data+strlen(data),block_verifiers_ip_address,strnlen(block_verifiers_ip_address,BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH)); \
  memcpy(data+strlen(data),"\nConnecting to another block verifier",37); \
  color_print(data,"red"); \
  if (reset_count >= MAXIMUM_DATABASE_SYNC_CONNECTIONS_ATTEMPTS) \
  { \
    exit(0); \
  } \
  else \
  { \
    reset_count++; \
    goto start; \
  }
  
  start:

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));
  memset(database_data,0,sizeof(database_data));
  memset(block_verifiers_ip_address,0,sizeof(block_verifiers_ip_address));

  // get a block verifier to sync the database from
  get_block_verifier_for_syncing_database(settings,DELEGATES_IP_ADDRESS,block_verifiers_ip_address,1);

  // get the current reserve bytes database
  get_reserve_bytes_database(current_reserve_bytes_database,0);
  
  // get the database data hash for the reserve bytes database
  if (test_settings == 0)
  {
    memset(data3,0,strlen(data3));
    memcpy(data3,"Getting the database data from ",31);
    memcpy(data3+31,block_verifiers_ip_address,strnlen(block_verifiers_ip_address,sizeof(block_verifiers_ip_address)));
    memcpy(data3+strlen(data3),"\n",sizeof(char));
    color_print(data3,"white");
  }
  if (get_database_data_hash(data,database_name,"reserve_bytes") == 0)
  {
    SYNC_RESERVE_BYTES_DATABASE_ERROR("Could not get the database data hash for the reserve bytes database from ");
  }

  // create the message
  memset(data3,0,strlen(data3));
  memcpy(data3,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE\",\r\n \"reserve_bytes_settings\": \"",136);
  snprintf(data3+strlen(data3),sizeof(data3)-138,"%d",RESERVE_BYTES_START_SETTINGS);
  memcpy(data3+strlen(data3),"\",\r\n \"reserve_bytes_data_hash\": \"",33);
  memcpy(data3+strlen(data3),data,DATA_HASH_LENGTH);
  memcpy(data3+strlen(data3),"\",\r\n ",5);
  count = RESERVE_BYTES_START_SETTINGS == 0 ? 1 : current_reserve_bytes_database - 1;
  if (count == 0)
  {
    // set it to only check the current reserve bytes database if their is no previous reserve bytes database
    count = 1;
  }

  for (; count <= current_reserve_bytes_database; count++)
  {
    memcpy(data3+strlen(data3),"\"reserve_bytes_data_hash_",25);
    snprintf(data3+strlen(data3),sizeof(data3)-1,"%zu",count);
    memcpy(data3+strlen(data3),"\": \"",4);
    // get the database data hash for the reserve bytes database
    memset(data,0,strlen(data));
    memset(data2,0,strlen(data2));  
    memcpy(data2,"reserve_bytes_",14);  
    snprintf(data2+14,MAXIMUM_NUMBER_SIZE,"%zu",count);
    if (get_database_data_hash(data,database_name,data2) == 0)
    {
      SYNC_RESERVE_BYTES_DATABASE_ERROR("Could not get the database data hash for the reserve bytes database from ");
    }
    memcpy(data3+strlen(data3),data,DATA_HASH_LENGTH);
    memcpy(data3+strlen(data3),"\",\r\n ",5);
  }
  memcpy(data3+strlen(data3),"}",sizeof(char));

  // sign_data
  if (sign_data(data3) == 0)
  { 
    SYNC_RESERVE_BYTES_DATABASE_ERROR("Could not sign_data");
  }

  // connect to the block verifier and get the database data
  if (send_and_receive_data_socket(database_data,sizeof(database_data),block_verifiers_ip_address,SEND_DATA_PORT,data3,DATABASE_SYNCING_TIMEOUT_SETTINGS) == 0)
  {
    SYNC_RESERVE_BYTES_DATABASE_ERROR("Could not receive data from ");
  }

  if (verify_data(database_data,0) == 0)
  {
    SYNC_RESERVE_BYTES_DATABASE_ERROR("Could not verify data from ");
  }

  count2 = RESERVE_BYTES_START_SETTINGS == 0 ? 1 : current_reserve_bytes_database - 1;
  if (count2 == 0)
  {
    // set it to only check the current reserve bytes database if their is no previous reserve bytes database
    count2 = 1;
  }

  // check if the block verifier needs to sync any of the reserve bytes databases and sync them if needed
  if (sync_check_reserve_bytes_specific_database(database_data,(const char*)block_verifiers_ip_address,count2,current_reserve_bytes_database) == 0)
  {
    SYNC_RESERVE_BYTES_DATABASE_ERROR("Could not check if any of the specific databases needed to be synced, from ");
  }
  return 1;
  
  #undef SYNC_RESERVE_BYTES_DATABASE_ERROR   
}



/// @brief Syncs the delegates database
/// @param settings 1 to sync from a random block verifier, 2 to sync from a random network data node, otherwise the index of the network data node to sync from + 3
/// @param DELEGATES_IP_ADDRESS The specific delegates IP address, if you are syncing directly from a delegate, otherwise an empty string
/// @return 0 if an error has occured, 1 if successfull
int sync_delegates_database(int settings, const char* DELEGATES_IP_ADDRESS)
{

  // check the light hard fork time and allocate more bytes
  // it's 2030 year
  // if (time(NULL) > TIME_SF_V_1_0_5_PART_1)
  // {
  //   // run the correct allocation function
  //   return sync_delegates_database_fixed(settings,DELEGATES_IP_ADDRESS);
  // }


  // Variables
  char* data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  char data2[BUFFER_SIZE];
  char database_data[BUFFER_SIZE];
  char block_verifiers_ip_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  int reset_count = 1;
  
  // define macros
  #define DATABASE_COLLECTION "delegates"
  #define MESSAGE "{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE\",\r\n}"
  #define SYNC_DELEGATES_DATABASE_ERROR(message) \
  memset(data,0,strlen(data)); \
  memcpy(data+strlen(data),message,strnlen(message,BUFFER_SIZE)); \
  memcpy(data+strlen(data),block_verifiers_ip_address,strnlen(block_verifiers_ip_address,BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH)); \
  memcpy(data+strlen(data),"\nConnecting to another block verifier",37); \
  color_print(data,"red"); \
  if (reset_count >= MAXIMUM_DATABASE_SYNC_CONNECTIONS_ATTEMPTS) \
  { \
    pointer_reset(data); \
    exit(0); \
  } \
  else \
  { \
    reset_count++; \
    goto start; \
  }

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL)
  {
    pointer_reset(data);
    memcpy(error_message.function[error_message.total],"sync_delegates_database",23);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,data2);  
    exit(0);
  }

  start:

  memset(data,0,strlen(data));
  memset(data2,0,sizeof(data2));
  memset(database_data,0,sizeof(database_data));
  memset(block_verifiers_ip_address,0,sizeof(block_verifiers_ip_address));

  // get a block verifier to sync the database from
  get_block_verifier_for_syncing_database(settings,DELEGATES_IP_ADDRESS,block_verifiers_ip_address,2);

  // get the database data hash for the delegates database
  if (test_settings == 0)
  {
    memset(data2,0,sizeof(data2));
    memcpy(data2,"Getting the database data from ",31);
    memcpy(data2+31,block_verifiers_ip_address,strnlen(block_verifiers_ip_address,sizeof(block_verifiers_ip_address)));
    memcpy(data2+strlen(data2),"\n",sizeof(char));
    color_print(data2,"white");
  }
  if (get_database_data_hash(data,database_name,DATABASE_COLLECTION) == 0)
  {
    SYNC_DELEGATES_DATABASE_ERROR("Could not get the database data hash for the delegates database from ");
  }

  // create the message
  memset(data2,0,strlen(data2));
  memcpy(data2,MESSAGE,sizeof(MESSAGE)-1);

  // sign_data
  if (sign_data(data2) == 0)
  { 
    SYNC_DELEGATES_DATABASE_ERROR("Could not sign_data");
  }     
  memset(data,0,strlen(data));

  // allow the database data to be received over the socket
  database_data_socket_settings = 1;

  if (send_and_receive_data_socket(data,MAXIMUM_BUFFER_SIZE,block_verifiers_ip_address,SEND_DATA_PORT,data2,DATABASE_SYNCING_TIMEOUT_SETTINGS) == 0)
  {
    database_data_socket_settings = 0;
    SYNC_DELEGATES_DATABASE_ERROR("Could not receive data from ");
  }
  database_data_socket_settings = 0;

  // parse the message
  memset(data2,0,strlen(data2));
  if (parse_json_data(data,"delegates_database",data2,sizeof(data2)) == 0)
  {
    SYNC_DELEGATES_DATABASE_ERROR("Could not receive data from ");
  }

  // delete the collection from the database
  // delete_collection_from_database(database_name,DATABASE_COLLECTION);

  // if the database is empty dont add any data
  if (strncmp(data2,DATABASE_EMPTY_STRING,BUFFER_SIZE) != 0)
  {
    // add the data to the database
    //data2[strlen(data2)-2] = 0;
    // insert_multiple_documents_into_collection_json(database_name,DATABASE_COLLECTION,data2,sizeof(data2));
    memset(data,0,strlen(data));
    memcpy(data,data2,strlen(data2)-2);
    upsert_json_to_db(database_name,XCASH_DB_DELEGATES, 0, data, false);
    // insert_multiple_documents_into_collection_json(database_name,DATABASE_COLLECTION,data,MAXIMUM_BUFFER_SIZE);
  }  

  pointer_reset(data);
  return 1;

  #undef DATABASE_COLLECTION
  #undef MESSAGE
  #undef SYNC_DELEGATES_DATABASE_ERROR   
}



/*
-----------------------------------------------------------------------------------------------------------
Name: sync_statistics_database
Description: Syncs the statistics database
Paramters:
  settings - 1 to sync from a random block verifier, 2 to sync from a random network data node, otherwise the index of the network data node to sync from + 3
  DELEGATES_IP_ADDRESS - The specific delegates IP address, if you are syncing directly from a delegate, otherwise an empty string
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int sync_statistics_database(int settings, const char* DELEGATES_IP_ADDRESS)
{
  // Variables
  char* data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  char data2[BUFFER_SIZE];
  char database_data[BUFFER_SIZE];
  char block_verifiers_ip_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  int reset_count = 1;
  
  // define macros
  #define DATABASE_COLLECTION "statistics"
  #define MESSAGE "{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_UPDATE\",\r\n}"
  #define SYNC_STATISTICS_DATABASE_ERROR(message) \
  memset(data,0,strlen(data)); \
  memcpy(data+strlen(data),message,strnlen(message,BUFFER_SIZE)); \
  memcpy(data+strlen(data),block_verifiers_ip_address,strnlen(block_verifiers_ip_address,BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH)); \
  memcpy(data+strlen(data),"\nConnecting to another block verifier",37); \
  color_print(data,"red"); \
  if (reset_count >= MAXIMUM_DATABASE_SYNC_CONNECTIONS_ATTEMPTS) \
  { \
    pointer_reset(data); \
    exit(0); \
  } \
  else \
  { \
    reset_count++; \
    goto start; \
  }

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL)
  {
    pointer_reset(data);
    memcpy(error_message.function[error_message.total],"sync_statistics_database",24);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,data2);
    exit(0);
  }

  start:

  memset(data,0,strlen(data));
  memset(data2,0,sizeof(data2));
  memset(database_data,0,sizeof(database_data));
  memset(block_verifiers_ip_address,0,sizeof(block_verifiers_ip_address));

  // get a block verifier to sync the database from
  get_block_verifier_for_syncing_database(settings,DELEGATES_IP_ADDRESS,block_verifiers_ip_address,3);

  // get the database data hash for the statistics database
  if (test_settings == 0)
  {
    memset(data2,0,sizeof(data2));
    memcpy(data2,"Getting the database data from ",31);
    memcpy(data2+31,block_verifiers_ip_address,strnlen(block_verifiers_ip_address,sizeof(block_verifiers_ip_address)));
    memcpy(data2+strlen(data2),"\n",sizeof(char));
    color_print(data2,"white");
  }
  if (get_database_data_hash(data,database_name,DATABASE_COLLECTION) == 0)
  {
    SYNC_STATISTICS_DATABASE_ERROR("Could not get the database data hash for the statistics database from ");
  }

  // create the message
  memset(data2,0,strlen(data2));
  memcpy(data2,MESSAGE,sizeof(MESSAGE)-1);

  // sign_data
  if (sign_data(data2) == 0)
  { 
    SYNC_STATISTICS_DATABASE_ERROR("Could not sign_data");
  }
  memset(data,0,strlen(data));

  // allow the database data to be received over the socket
  database_data_socket_settings = 1;

  if (send_and_receive_data_socket(data,MAXIMUM_BUFFER_SIZE,block_verifiers_ip_address,SEND_DATA_PORT,data2,SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS) == 0)
  {
    database_data_socket_settings = 0;
    SYNC_STATISTICS_DATABASE_ERROR("Could not receive data from ");
  }
  database_data_socket_settings = 0;

  // parse the message
  memset(data2,0,strlen(data2));
  if (parse_json_data(data,"statistics_database",data2,sizeof(data2)) == 0)
  {
    SYNC_STATISTICS_DATABASE_ERROR("Could not receive data from ");
  }


  // FIXME we can't delete the database it caused problems

  // // delete the collection from the database
  // delete_collection_from_database(database_name,DATABASE_COLLECTION);

  // if the database is empty dont add any data
  if (strncmp(data2,DATABASE_EMPTY_STRING,BUFFER_SIZE) != 0)
  {
    // add the data to the database
    //data2[strlen(data2)-2] = 0;
    //insert_document_into_collection_json(database_name,DATABASE_COLLECTION,data2);
    memset(data,0,strlen(data));
    memcpy(data,data2,strlen(data2)-2);
    insert_document_into_collection_json(database_name,DATABASE_COLLECTION,data);
  }

  pointer_reset(data);
  return 1;

  #undef DATABASE_COLLECTION
  #undef MESSAGE
  #undef SYNC_STATISTICS_DATABASE_ERROR   
}



/*
-----------------------------------------------------------------------------------------------------------
Name: sync_delegates_database_fixed
Description: Syncs the delegates database (with the correct bytes allocated)
Paramters:
  settings - 1 to sync from a random block verifier, 2 to sync from a random network data node, otherwise the index of the network data node to sync from + 3
  DELEGATES_IP_ADDRESS - The specific delegates IP address, if you are syncing directly from a delegate, otherwise an empty string
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int sync_delegates_database_fixed(int settings, const char* DELEGATES_IP_ADDRESS)
{
  // Variables
  char* data = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  char* data2 = (char*)calloc(MAXIMUM_BUFFER_SIZE,sizeof(char));
  char buffer[BUFFER_SIZE];
  char block_verifiers_ip_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  int reset_count = 1;
  
  // define macros
  #define pointer_reset_all \
  free(data); \
  data = NULL; \
  free(data2); \
  data2 = NULL;

  #define DATABASE_COLLECTION "delegates"
  #define MESSAGE "{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE\",\r\n}"
  #define SYNC_DELEGATES_DATABASE_ERROR(message) \
  memset(data,0,strlen(data)); \
  memcpy(data+strlen(data),message,strnlen(message,BUFFER_SIZE)); \
  memcpy(data+strlen(data),block_verifiers_ip_address,strnlen(block_verifiers_ip_address,BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH)); \
  memcpy(data+strlen(data),"\nConnecting to another block verifier",37); \
  color_print(data,"red"); \
  if (reset_count >= MAXIMUM_DATABASE_SYNC_CONNECTIONS_ATTEMPTS) \
  { \
    pointer_reset_all; \
    exit(0); \
  } \
  else \
  { \
    reset_count++; \
    goto start; \
  }

  memset(buffer,0,sizeof(buffer));

  // check if the memory needed was allocated on the heap successfully
  if (data == NULL || data2 == NULL)
  {
    memcpy(error_message.function[error_message.total],"sync_delegates_database",23);
    memcpy(error_message.data[error_message.total],"Could not allocate the memory needed on the heap",48);
    error_message.total++;
    print_error_message(current_date_and_time,current_UTC_date_and_time,buffer);  
    exit(0);
  }

  start:

  memset(data,0,strlen(data));
  memset(data2,0,strlen(data2));
  memset(block_verifiers_ip_address,0,sizeof(block_verifiers_ip_address));

  // get a block verifier to sync the database from
  get_block_verifier_for_syncing_database(settings,DELEGATES_IP_ADDRESS,block_verifiers_ip_address,2);

  // get the database data hash for the delegates database
  if (test_settings == 0)
  {
    memset(data2,0,strlen(data2));
    memcpy(data2,"Getting the database data from ",31);
    memcpy(data2+31,block_verifiers_ip_address,strnlen(block_verifiers_ip_address,BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH));
    memcpy(data2+strlen(data2),"\n",sizeof(char));
    color_print(data2,"white");
  }
  if (get_database_data_hash(data,database_name,DATABASE_COLLECTION) == 0)
  {
    SYNC_DELEGATES_DATABASE_ERROR("Could not get the database data hash for the delegates database from ");
  }

  // create the message
  memset(data2,0,strlen(data2));
  memcpy(data2,MESSAGE,sizeof(MESSAGE)-1);

  // sign_data
  if (sign_data(data2) == 0)
  { 
    SYNC_DELEGATES_DATABASE_ERROR("Could not sign_data");
  }     
  memset(data,0,strlen(data));

  // allow the database data to be received over the socket
  database_data_socket_settings = 1;

  if (send_and_receive_data_socket(data,MAXIMUM_BUFFER_SIZE,block_verifiers_ip_address,SEND_DATA_PORT,data2,DATABASE_SYNCING_TIMEOUT_SETTINGS) == 0)
  {
    database_data_socket_settings = 0;
    SYNC_DELEGATES_DATABASE_ERROR("Could not receive data from ");
  }
  database_data_socket_settings = 0;

  // parse the message
  memset(data2,0,strlen(data2));
  if (parse_json_data(data,"delegates_database",data2,MAXIMUM_BUFFER_SIZE) == 0)
  {
    SYNC_DELEGATES_DATABASE_ERROR("Could not receive data from ");
  }

  // delete the collection from the database
  // delete_collection_from_database(database_name,DATABASE_COLLECTION);

  // if the database is empty dont add any data
  if (strncmp(data2,DATABASE_EMPTY_STRING,BUFFER_SIZE) != 0)
  {
    // add the data to the database
    //data2[strlen(data2)-2] = 0;
    // insert_multiple_documents_into_collection_json(database_name,DATABASE_COLLECTION,data2,sizeof(data2));
    memset(data,0,strlen(data));
    memcpy(data,data2,strlen(data2)-2);
    upsert_json_to_db(database_name, XCASH_DB_DELEGATES, 0, data, false);
    // insert_multiple_documents_into_collection_json(database_name,DATABASE_COLLECTION,data,MAXIMUM_BUFFER_SIZE);
  }  

  pointer_reset_all;
  return 1;

  #undef pointer_reset_all
  #undef DATABASE_COLLECTION
  #undef MESSAGE
  #undef SYNC_DELEGATES_DATABASE_ERROR   
}
