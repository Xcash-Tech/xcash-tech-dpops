#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h> 
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>

#include "define_macro_functions.h"
#include "define_macros.h"
#include "define_macros_test.h"
#include "structures.h"
#include "variables.h"

#include "blockchain_functions.h"
#include "block_verifiers_functions.h"
#include "block_verifiers_synchronize_check_functions.h"
#include "block_verifiers_synchronize_server_functions.h"
#include "block_verifiers_synchronize_functions.h"
#include "block_verifiers_thread_server_functions.h"
#include "block_verifiers_update_functions.h"
#include "database_functions.h"
#include "count_database_functions.h"
#include "insert_database_functions.h"
#include "read_database_functions.h"
#include "update_database_functions.h"
#include "delete_database_functions.h"
#include "file_functions.h"
#include "network_daemon_functions.h"
#include "network_functions.h"
#include "network_security_functions.h"
#include "network_wallet_functions.h"
// #include "organize_functions.h"
#include "string_functions.h"
#include "thread_functions.h"
#include "convert.h"
#include "vrf.h"
#include "crypto_vrf.h"
#include "VRF_functions.h"
#include "sha512EL.h"


#include "xcash_message.h"
#include "xcash_net.h"

#include "uv_net.h"
#include "xcash_db_sync.h"
#include "xcash_db_helpers.h"

#include "round.h"

/*
-----------------------------------------------------------------------------------------------------------
Functions
-----------------------------------------------------------------------------------------------------------
*/




/*
-----------------------------------------------------------------------------------------------------------
Name: start_blocks_create_vrf_data
Description: Creates the VRF data for the start block
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int start_blocks_create_vrf_data(void)
{
  // Variables
  size_t count;
  size_t count2;

  // define macros
  #define START_BLOCKS_CREATE_VRF_DATA_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"start_blocks_create_vrf_data",28); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  return 0;

  if (create_random_VRF_keys(VRF_data.vrf_public_key,VRF_data.vrf_secret_key) == 1 && crypto_vrf_is_valid_key((const unsigned char*)VRF_data.vrf_public_key) != 1)
  {
    START_BLOCKS_CREATE_VRF_DATA_ERROR("Could not create the vrf_public_key or vrf_secret_key");
  }

  memset(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,0,strlen(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data));
  memset(blockchain_data.previous_block_hash_data,0,strlen(blockchain_data.previous_block_hash_data));
  memset(VRF_data.vrf_alpha_string,0,strlen((char*)VRF_data.vrf_alpha_string));    
  memcpy(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,previous_block_hash,BLOCK_HASH_LENGTH);
  memcpy(blockchain_data.previous_block_hash_data,previous_block_hash,BLOCK_HASH_LENGTH);
  memcpy(VRF_data.vrf_alpha_string,previous_block_hash,BLOCK_HASH_LENGTH);
  blockchain_data.previous_block_hash_data_length = BLOCK_HASH_LENGTH;
  blockchain_data.blockchain_reserve_bytes.previous_block_hash_data_length = BLOCK_HASH_LENGTH;

  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    memcpy(VRF_data.vrf_alpha_string+strlen((const char*)VRF_data.vrf_alpha_string),GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING)-1);
  }   

  // convert the vrf alpha string to a string
  for (count2 = 0, count = 0; count2 < (((RANDOM_STRING_LENGTH*2)*BLOCK_VERIFIERS_AMOUNT) + (BLOCK_HASH_LENGTH*2)) / 2; count2++, count += 2)
  {
    snprintf(VRF_data.vrf_alpha_string_data+count,BUFFER_SIZE-1,"%02x",VRF_data.vrf_alpha_string[count2] & 0xFF);
  }

  if (crypto_vrf_prove(VRF_data.vrf_proof,(const unsigned char*)VRF_data.vrf_secret_key,(const unsigned char*)VRF_data.vrf_alpha_string_data,(unsigned long long)strlen((const char*)VRF_data.vrf_alpha_string_data)) != 0)
  {
    START_BLOCKS_CREATE_VRF_DATA_ERROR("Could not create the vrf proof");
  }
  if (crypto_vrf_proof_to_hash(VRF_data.vrf_beta_string,(const unsigned char*)VRF_data.vrf_proof) != 0)
  {
    START_BLOCKS_CREATE_VRF_DATA_ERROR("Could not create the vrf beta string");
  }
  if (crypto_vrf_verify(VRF_data.vrf_beta_string,(const unsigned char*)VRF_data.vrf_public_key,(const unsigned char*)VRF_data.vrf_proof,(const unsigned char*)VRF_data.vrf_alpha_string_data,(unsigned long long)strlen((const char*)VRF_data.vrf_alpha_string_data)) != 0)
  {
    START_BLOCKS_CREATE_VRF_DATA_ERROR("Could not create the VRF data");
  }

  // convert all of the VRF data to a string
  for (count2 = 0, count = 0; count2 < crypto_vrf_SECRETKEYBYTES; count2++, count += 2)
  {
    snprintf(VRF_data.vrf_secret_key_data+count,BUFFER_SIZE_NETWORK_BLOCK_DATA-1,"%02x",VRF_data.vrf_secret_key[count2] & 0xFF);
  }
  for (count2 = 0, count = 0; count2 < crypto_vrf_PUBLICKEYBYTES; count2++, count += 2)
  {
    snprintf(VRF_data.vrf_public_key_data+count,BUFFER_SIZE_NETWORK_BLOCK_DATA-1,"%02x",VRF_data.vrf_public_key[count2] & 0xFF);
  }
  for (count2 = 0, count = 0; count2 < crypto_vrf_PROOFBYTES; count2++, count += 2)
  {
    snprintf(VRF_data.vrf_proof_data+count,BUFFER_SIZE_NETWORK_BLOCK_DATA-1,"%02x",VRF_data.vrf_proof[count2] & 0xFF);
  }
  for (count2 = 0, count = 0; count2 < crypto_vrf_OUTPUTBYTES; count2++, count += 2)
  {
    snprintf(VRF_data.vrf_beta_string_data+count,BUFFER_SIZE_NETWORK_BLOCK_DATA-1,"%02x",VRF_data.vrf_beta_string[count2] & 0xFF);
  }  

  // add all of the VRF data to the blockchain_data struct
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_secret_key,VRF_data.vrf_secret_key,crypto_vrf_SECRETKEYBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data,VRF_data.vrf_secret_key_data,VRF_SECRET_KEY_LENGTH);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_public_key,VRF_data.vrf_public_key,crypto_vrf_PUBLICKEYBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data,VRF_data.vrf_public_key_data,VRF_PUBLIC_KEY_LENGTH);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string,VRF_data.vrf_alpha_string,strnlen((const char*)VRF_data.vrf_alpha_string,BUFFER_SIZE));
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data,VRF_data.vrf_alpha_string_data,strnlen(VRF_data.vrf_alpha_string_data,BUFFER_SIZE));
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_proof,VRF_data.vrf_proof,crypto_vrf_PROOFBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_proof_data,VRF_data.vrf_proof_data,VRF_PROOF_LENGTH);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_beta_string,VRF_data.vrf_beta_string,crypto_vrf_OUTPUTBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data,VRF_data.vrf_beta_string_data,VRF_BETA_LENGTH);

  memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[0],blockchain_data.blockchain_reserve_bytes.vrf_secret_key,crypto_vrf_SECRETKEYBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[0],blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data,VRF_SECRET_KEY_LENGTH);
  memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[0],blockchain_data.blockchain_reserve_bytes.vrf_public_key,crypto_vrf_PUBLICKEYBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[0],blockchain_data.blockchain_reserve_bytes.vrf_public_key_data,VRF_PUBLIC_KEY_LENGTH);
  memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[0],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING)-1);
  
  for (count = 1; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA)-1);
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA)-1);
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING)-1);
  }
  return 1;

  #undef START_BLOCKS_CREATE_VRF_DATA_ERROR
}




/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_create_VRF_secret_key_and_VRF_public_key
Description: The block verifiers will create a VRF secret key and a VRF public key
Parameters:
  message - The message to send to the block verifiers
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int block_verifiers_create_VRF_secret_key_and_VRF_public_key(char* message)
{
  // Variables
  char data[SMALL_BUFFER_SIZE];
  size_t count;
  size_t counter;

  // define macros
  #define BLOCK_VERIFIERS_CREATE_VRF_SECRET_KEY_AND_VRF_PUBLIC_KEY_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"block_verifiers_create_VRF_secret_key_and_VRF_public_key",56); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  return 0; 

  memset(data,0,sizeof(data));
  
  // create a random VRF public key and secret key
  if (create_random_VRF_keys(VRF_data.vrf_public_key,VRF_data.vrf_secret_key) != 1 || crypto_vrf_is_valid_key((const unsigned char*)VRF_data.vrf_public_key) != 1)
  {
    BLOCK_VERIFIERS_CREATE_VRF_SECRET_KEY_AND_VRF_PUBLIC_KEY_ERROR("Could not create the VRF secret key or VRF public key for the VRF data");
  }  

  // convert the VRF secret key to hexadecimal
  for (count = 0, counter = 0; count < crypto_vrf_SECRETKEYBYTES; count++, counter += 2)
  {
    snprintf(VRF_data.vrf_secret_key_data+counter,BUFFER_SIZE_NETWORK_BLOCK_DATA-1,"%02x",VRF_data.vrf_secret_key[count] & 0xFF);
  }

  // convert the VRF public key to hexadecimal
  for (count = 0, counter = 0; count < crypto_vrf_PUBLICKEYBYTES; count++, counter += 2)
  {
    snprintf(VRF_data.vrf_public_key_data+counter,BUFFER_SIZE_NETWORK_BLOCK_DATA-1,"%02x",VRF_data.vrf_public_key[count] & 0xFF);
  } 

  // create the message
  memset(message,0,strlen(message));
  memcpy(message,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_VRF_DATA\",\r\n \"vrf_secret_key\": \"",92);
  memcpy(message+92,VRF_data.vrf_secret_key_data,VRF_SECRET_KEY_LENGTH);
  memcpy(message+220,"\",\r\n \"vrf_public_key\": \"",24);
  memcpy(message+244,VRF_data.vrf_public_key_data,VRF_PUBLIC_KEY_LENGTH);
  memcpy(message+308,"\",\r\n \"random_data\": \"",21);
  
  // create random data to use in the alpha string of the VRF data
  if (random_string(data,RANDOM_STRING_LENGTH) == 0)
  {
    BLOCK_VERIFIERS_CREATE_VRF_SECRET_KEY_AND_VRF_PUBLIC_KEY_ERROR("Could not create random data for the VRF data");
  }

  memcpy(message+329,data,RANDOM_STRING_LENGTH);
  memcpy(message+429,"\",\r\n}",5);

  // add the VRF data to the block verifiers VRF data copy
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0)
    {        
      memcpy(VRF_data.block_verifiers_vrf_secret_key[count],VRF_data.vrf_secret_key,crypto_vrf_SECRETKEYBYTES);
      memcpy(VRF_data.block_verifiers_vrf_secret_key_data[count],VRF_data.vrf_secret_key_data,VRF_SECRET_KEY_LENGTH);
      memcpy(VRF_data.block_verifiers_vrf_public_key[count],VRF_data.vrf_public_key,crypto_vrf_PUBLICKEYBYTES);
      memcpy(VRF_data.block_verifiers_vrf_public_key_data[count],VRF_data.vrf_public_key_data,VRF_PUBLIC_KEY_LENGTH);
      memcpy(VRF_data.block_verifiers_random_data[count],data,RANDOM_STRING_LENGTH);
    }
  } 
  return 1;

  #undef BLOCK_VERIFIERS_CREATE_VRF_SECRET_KEY_AND_VRF_PUBLIC_KEY_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_create_VRF_data
Description: The block verifiers will create all of the VRF data
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int block_verifiers_create_VRF_data(void)
{
  // Variables
  char data[SMALL_BUFFER_SIZE];
  char data2[SMALL_BUFFER_SIZE];
  size_t count;
  size_t count2;
  size_t counter;

  // define macros
  #define BLOCK_VERIFIERS_CREATE_VRF_DATA_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"block_verifiers_create_VRF_data",31); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  return 0; 

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));

  // create the VRF alpha string using all of the random data from the block verifiers
  memset(VRF_data.vrf_alpha_string,0,strlen((const char*)VRF_data.vrf_alpha_string));
  memcpy(VRF_data.vrf_alpha_string,previous_block_hash,BLOCK_HASH_LENGTH);

  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) {
      if (strlen((const char*)VRF_data.block_verifiers_vrf_secret_key[count]) == crypto_vrf_SECRETKEYBYTES &&
          strlen((const char*)VRF_data.block_verifiers_vrf_public_key[count]) == crypto_vrf_PUBLICKEYBYTES &&
          strlen(VRF_data.block_verifiers_random_data[count]) == RANDOM_STRING_LENGTH) {
          memcpy(VRF_data.vrf_alpha_string + strlen((const char*)VRF_data.vrf_alpha_string),
                 VRF_data.block_verifiers_random_data[count], RANDOM_STRING_LENGTH);
      } else {
          memcpy(VRF_data.vrf_alpha_string + strlen((const char*)VRF_data.vrf_alpha_string),
                 GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,
                 sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING) - 1);
      }
  }

  // convert the vrf alpha string to a string
  for (count2 = 0, count = 0; count2 < (((RANDOM_STRING_LENGTH*2)*BLOCK_VERIFIERS_AMOUNT) + (BLOCK_HASH_LENGTH*2)) / 2; count2++, count += 2)
  {
    snprintf(VRF_data.vrf_alpha_string_data+count,BUFFER_SIZE-1,"%02x",VRF_data.vrf_alpha_string[count2] & 0xFF);
  }
  
  crypto_hash_sha512((unsigned char*)data,(const unsigned char*)VRF_data.vrf_alpha_string_data,strlen(VRF_data.vrf_alpha_string_data));

  // convert the SHA512 data hash to a string
  for (count2 = 0, count = 0; count2 < DATA_HASH_LENGTH / 2; count2++, count += 2)
  {
    snprintf(data2+count,sizeof(data2)-1,"%02x",data[count2] & 0xFF);
  }

  // check what block verifiers vrf secret key and vrf public key to use
  for (count = 0; count < DATA_HASH_LENGTH; count += 2)
  {
    memset(data,0,sizeof(data));
    memcpy(data,&data2[count],2);
    counter = (int)strtol(data, NULL, 16); 
   
    /* if it is not in the range of 01 - FA or it has already been calculated then skip the byte
       This number needs to be evenly divisible by how many maximum block verifiers there will be
       This is so block verifiers in specific spots do not have more of a chance to be the block producer than others
       The goal is to use as many bytes as possible, since the more unused bytes, the more chance that it will run out of bytes when selecting the block producer
    */
    if (counter >= MINIMUM_BYTE_RANGE && counter <= MAXIMUM_BYTE_RANGE)
    {
      counter = counter % BLOCK_VERIFIERS_AMOUNT;

      // check if the block verifier created the data
      if (strncmp(VRF_data.block_verifiers_vrf_secret_key_data[counter],
                  GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA,
                  sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA) - 1) != 0 &&
          strncmp(VRF_data.block_verifiers_vrf_public_key_data[counter],
                  GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA,
                  sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA) - 1) != 0 &&
          strncmp(VRF_data.block_verifiers_random_data[counter], GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,
                  sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING) - 1) != 0) {
          break;
      }
    }
  }

  // create all of the VRF data
  memcpy(VRF_data.vrf_secret_key_data,VRF_data.block_verifiers_vrf_secret_key_data[counter],VRF_SECRET_KEY_LENGTH);
  memcpy(VRF_data.vrf_secret_key,VRF_data.block_verifiers_vrf_secret_key[counter],crypto_vrf_SECRETKEYBYTES);
  memcpy(VRF_data.vrf_public_key_data,VRF_data.block_verifiers_vrf_public_key_data[counter],VRF_PUBLIC_KEY_LENGTH);
  memcpy(VRF_data.vrf_public_key,VRF_data.block_verifiers_vrf_public_key[counter],crypto_vrf_PUBLICKEYBYTES);

  if (crypto_vrf_prove(VRF_data.vrf_proof,(const unsigned char*)VRF_data.vrf_secret_key,(const unsigned char*)VRF_data.vrf_alpha_string_data,(unsigned long long)strlen((const char*)VRF_data.vrf_alpha_string_data)) != 0)
  {
    BLOCK_VERIFIERS_CREATE_VRF_DATA_ERROR("Could not create the vrf proof");
  }
  if (crypto_vrf_proof_to_hash(VRF_data.vrf_beta_string,(const unsigned char*)VRF_data.vrf_proof) != 0)
  {
    BLOCK_VERIFIERS_CREATE_VRF_DATA_ERROR("Could not create the vrf beta string");
  }
  if (crypto_vrf_verify(VRF_data.vrf_beta_string,(const unsigned char*)VRF_data.vrf_public_key,(const unsigned char*)VRF_data.vrf_proof,(const unsigned char*)VRF_data.vrf_alpha_string_data,(unsigned long long)strlen((const char*)VRF_data.vrf_alpha_string_data)) != 0)
  {
    BLOCK_VERIFIERS_CREATE_VRF_DATA_ERROR("Could not create the VRF data");
  }

  // convert the vrf proof and vrf beta string to a string
  for (counter = 0, count = 0; counter < crypto_vrf_PROOFBYTES; counter++, count += 2)
  {
    snprintf(VRF_data.vrf_proof_data+count,BUFFER_SIZE_NETWORK_BLOCK_DATA-1,"%02x",VRF_data.vrf_proof[counter] & 0xFF);
  }
  for (counter = 0, count = 0; counter < crypto_vrf_OUTPUTBYTES; counter++, count += 2)
  {
    snprintf(VRF_data.vrf_beta_string_data+count,BUFFER_SIZE_NETWORK_BLOCK_DATA-1,"%02x",VRF_data.vrf_beta_string[counter] & 0xFF);
  }
  return 1;

  #undef BLOCK_VERIFIERS_CREATE_VRF_DATA_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_create_block_signature
Description: The block verifiers will create the block signature
Parameters:
  message - The message to send to the block verifiers
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int block_verifiers_create_block_signature(char* message)
{
  // Variables
  char data[BUFFER_SIZE];
  size_t count;
  size_t count2;
  size_t counter;
  int block_producer_backup_settings[BLOCK_PRODUCERS_BACKUP_AMOUNT] = {0,0,0,0,0};

  // define macros
  #define BLOCK_VERIFIERS_CREATE_BLOCK_SIGNATURE_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"block_verifiers_create_block_signature",38); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  return 0; 

  memset(data,0,sizeof(data));

  // convert the network block string to a blockchain data
  if (network_block_string_to_blockchain_data(VRF_data.block_blob,"0",BLOCK_VERIFIERS_AMOUNT) == 0)
  {
    BLOCK_VERIFIERS_CREATE_BLOCK_SIGNATURE_ERROR("Could not convert the network block string to a blockchain data");
  }

  // change the network block nonce to the block producer network block nonce
  memcpy(blockchain_data.nonce_data,BLOCK_PRODUCER_NETWORK_BLOCK_NONCE,sizeof(BLOCK_PRODUCER_NETWORK_BLOCK_NONCE)-1);

  // get the current block producer
  if (strncmp(current_round_part_backup_node,"0",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_public_address,sizeof(main_nodes_list.block_producer_public_address)) == 0)
      {
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,current_block_verifiers_list.block_verifiers_name[count],strnlen(current_block_verifiers_list.block_verifiers_name[count],sizeof(current_block_verifiers_list.block_verifiers_name[count]))); 
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"1",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_1_public_address,sizeof(current_block_verifiers_list.block_verifiers_public_address[count])) == 0)
      {
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,current_block_verifiers_list.block_verifiers_name[count],strnlen(current_block_verifiers_list.block_verifiers_name[count],sizeof(current_block_verifiers_list.block_verifiers_name[count]))); 
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"2",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_2_public_address,sizeof(current_block_verifiers_list.block_verifiers_public_address[count])) == 0)
      {
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,current_block_verifiers_list.block_verifiers_name[count],strnlen(current_block_verifiers_list.block_verifiers_name[count],sizeof(current_block_verifiers_list.block_verifiers_name[count]))); 
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"3",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_3_public_address,sizeof(current_block_verifiers_list.block_verifiers_public_address[count])) == 0)
      {
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,current_block_verifiers_list.block_verifiers_name[count],strnlen(current_block_verifiers_list.block_verifiers_name[count],sizeof(current_block_verifiers_list.block_verifiers_name[count]))); 
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"4",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_4_public_address,sizeof(current_block_verifiers_list.block_verifiers_public_address[count])) == 0)
      {
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,current_block_verifiers_list.block_verifiers_name[count],strnlen(current_block_verifiers_list.block_verifiers_name[count],sizeof(current_block_verifiers_list.block_verifiers_name[count])));
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"5",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_5_public_address,sizeof(current_block_verifiers_list.block_verifiers_public_address[count])) == 0)
      {
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_delegates_name,current_block_verifiers_list.block_verifiers_name[count],strnlen(current_block_verifiers_list.block_verifiers_name[count],sizeof(current_block_verifiers_list.block_verifiers_name[count])));
        memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH);
        break;
      }
    }
  }

  // add all of the VRF data to the blockchain_data struct  
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {    
    if (strncmp(main_nodes_list.block_producer_backup_block_verifier_1_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH) == 0)
    {
      block_producer_backup_settings[0] = (int)count;
    }
    if (strncmp(main_nodes_list.block_producer_backup_block_verifier_2_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH) == 0)
    {
      block_producer_backup_settings[1] = (int)count;
    }
    if (strncmp(main_nodes_list.block_producer_backup_block_verifier_3_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH) == 0)
    {
      block_producer_backup_settings[2] = (int)count;
    }
    if (strncmp(main_nodes_list.block_producer_backup_block_verifier_4_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH) == 0)
    {
      block_producer_backup_settings[3] = (int)count;
    }
    if (strncmp(main_nodes_list.block_producer_backup_block_verifier_5_public_address,current_block_verifiers_list.block_verifiers_public_address[count],XCASH_WALLET_LENGTH) == 0)
    {
      block_producer_backup_settings[4] = (int)count;
    }
  }

  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_node_backup_count,current_round_part_backup_node,sizeof(char));
    
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[0]],strnlen(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[0]],sizeof(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[0]])));
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),",",sizeof(char));
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[1]],strnlen(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[1]],sizeof(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[1]])));
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),",",sizeof(char));
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[2]],strnlen(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[2]],sizeof(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[2]])));
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),",",sizeof(char));
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[3]],strnlen(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[3]],sizeof(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[3]])));
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),",",sizeof(char));
  memcpy(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names+strlen(blockchain_data.blockchain_reserve_bytes.block_producer_backup_nodes_names),current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[4]],strnlen(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[4]],sizeof(current_block_verifiers_list.block_verifiers_name[block_producer_backup_settings[4]])));

  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_secret_key,VRF_data.vrf_secret_key,crypto_vrf_SECRETKEYBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_secret_key_data,VRF_data.vrf_secret_key_data,VRF_SECRET_KEY_LENGTH);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_public_key,VRF_data.vrf_public_key,crypto_vrf_PUBLICKEYBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_public_key_data,VRF_data.vrf_public_key_data,VRF_PUBLIC_KEY_LENGTH);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string,VRF_data.vrf_alpha_string,strnlen((const char*)VRF_data.vrf_alpha_string,BUFFER_SIZE));
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_alpha_string_data,VRF_data.vrf_alpha_string_data,strnlen(VRF_data.vrf_alpha_string_data,BUFFER_SIZE));
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_proof,VRF_data.vrf_proof,crypto_vrf_PROOFBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_proof_data,VRF_data.vrf_proof_data,VRF_PROOF_LENGTH);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_beta_string,VRF_data.vrf_beta_string,crypto_vrf_OUTPUTBYTES);
  memcpy(blockchain_data.blockchain_reserve_bytes.vrf_beta_string_data,VRF_data.vrf_beta_string_data,VRF_BETA_LENGTH);

  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key[count],VRF_data.block_verifiers_vrf_secret_key[count],crypto_vrf_SECRETKEYBYTES);
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key[count],VRF_data.block_verifiers_vrf_public_key[count],crypto_vrf_PUBLICKEYBYTES);
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_secret_key_data[count],VRF_data.block_verifiers_vrf_secret_key_data[count],VRF_SECRET_KEY_LENGTH);
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_vrf_public_key_data[count],VRF_data.block_verifiers_vrf_public_key_data[count],VRF_PUBLIC_KEY_LENGTH);
    memcpy(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data_text[count],VRF_data.block_verifiers_random_data[count],RANDOM_STRING_LENGTH);

    memcpy(blockchain_data.blockchain_reserve_bytes.next_block_verifiers_public_address[count],next_block_verifiers_list.block_verifiers_public_key[count],VRF_PUBLIC_KEY_LENGTH);
    memcpy(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature_data[count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE_DATA,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE_DATA)-1);
    memcpy(blockchain_data.blockchain_reserve_bytes.block_validation_node_signature[count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE)-1);
            
    for (counter = 0, count2 = 0; counter < RANDOM_STRING_LENGTH; counter++, count2 += 2)
    {
      snprintf(blockchain_data.blockchain_reserve_bytes.block_verifiers_random_data[count]+count2,RANDOM_STRING_LENGTH,"%02x",VRF_data.block_verifiers_random_data[count][counter] & 0xFF);
    }
  }

  memcpy(blockchain_data.blockchain_reserve_bytes.previous_block_hash_data,blockchain_data.previous_block_hash_data,BLOCK_HASH_LENGTH);

  // convert the blockchain_data to a network_block_string
  if (blockchain_data_to_network_block_string(VRF_data.block_blob,BLOCK_VERIFIERS_AMOUNT) == 0)
  {
    BLOCK_VERIFIERS_CREATE_BLOCK_SIGNATURE_ERROR("Could not convert the blockchain_data to a network_block_string");
  }

  // sign the network block string
  memset(data,0,sizeof(data));
  if (sign_network_block_string(data,VRF_data.block_blob) == 0)
  {
    BLOCK_VERIFIERS_CREATE_BLOCK_SIGNATURE_ERROR("Could not sign the network block string");
  }

  // add the block verifier signature to the VRF data and the blockchain_data struct
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0)
    {
      memcpy(VRF_data.block_blob_signature[count],data,strnlen(data,BUFFER_SIZE));
    }
  }

  // create the message
  memset(message,0,strlen(message));
  memcpy(message,"{\r\n \"message_settings\": \"BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_BLOCK_BLOB_SIGNATURE\",\r\n \"block_blob_signature\": \"",110);
  memcpy(message+110,data,strnlen(data,BUFFER_SIZE));
  memcpy(message+strlen(message),"\",\r\n}",5);
  return 1;

  #undef BLOCK_VERIFIERS_CREATE_BLOCK_SIGNATURE_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_create_vote_majority_results
Description: The block verifiers will create the vote majority results
Parameters:
  result - The result
  SETTINGS - The data settings
-----------------------------------------------------------------------------------------------------------
*/

void block_verifiers_create_vote_majority_results(char *result, const int SETTINGS)
{
  // variables
  int count;
  int count2;

  memset(result,0,strlen(result));


  // FIXME potentially concurency problem when server already receives data but we didn't finish preparing

  // reset the current_block_verifiers_majority_vote
  // for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  // {
  //   for (count2 = 0; count2 < BLOCK_VERIFIERS_AMOUNT; count2++)
  //   {
  //     memset(current_block_verifiers_majority_vote.data[count][count2],0,sizeof(current_block_verifiers_majority_vote.data[count][count2]));
  //   }
  // }

  // create the message
  memcpy(result,"{\r\n \"message_settings\": \"NODES_TO_NODES_VOTE_MAJORITY_RESULTS\",\r\n ",66);
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    memcpy(result+strlen(result),"\"vote_data_",11);
    snprintf(result+strlen(result),MAXIMUM_NUMBER_SIZE,"%d",count+1);
    memcpy(result+strlen(result),"\": \"",4);

    // create the data
    if (SETTINGS == 0)
    {
        if (strlen(VRF_data.block_verifiers_vrf_secret_key_data[count]) == VRF_SECRET_KEY_LENGTH &&
            strlen(VRF_data.block_verifiers_vrf_public_key_data[count]) == VRF_PUBLIC_KEY_LENGTH &&
            strlen(VRF_data.block_verifiers_random_data[count]) == RANDOM_STRING_LENGTH) {
            memcpy(result + strlen(result), VRF_data.block_verifiers_vrf_secret_key_data[count], VRF_SECRET_KEY_LENGTH);
            memcpy(result + strlen(result), VRF_data.block_verifiers_vrf_public_key_data[count], VRF_PUBLIC_KEY_LENGTH);
            memcpy(result + strlen(result), VRF_data.block_verifiers_random_data[count], RANDOM_STRING_LENGTH);
        } else {
            // the block verifier did not send any data
            memcpy(result + strlen(result), BLOCK_VERIFIER_MAJORITY_VRF_DATA_TEMPLATE,
                   sizeof(BLOCK_VERIFIER_MAJORITY_VRF_DATA_TEMPLATE) - 1);
        }
    }
    else
    {
      if (strlen(VRF_data.block_blob_signature[count]) == VRF_PROOF_LENGTH+VRF_BETA_LENGTH)
      {
        memcpy(result+strlen(result),VRF_data.block_blob_signature[count],VRF_PROOF_LENGTH+VRF_BETA_LENGTH);
      }
      else
      {
        // the block verifier did not send any data
        memcpy(result+strlen(result),BLOCK_VERIFIER_MAJORITY_BLOCK_VERIFIERS_SIGNATURE_TEMPLATE,sizeof(BLOCK_VERIFIER_MAJORITY_BLOCK_VERIFIERS_SIGNATURE_TEMPLATE)-1);
      }      
    }
    memcpy(result+strlen(result),"\",\r\n ",5);
  }
  memcpy(result+strlen(result)-1,"}",1);

  // add your own data to the current block verifiers majority vote
  for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
  {
    if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0)
    {
      break;
    }
  }

  for (count2 = 0; count2 < BLOCK_VERIFIERS_AMOUNT; count2++)
  {
    memcpy(current_block_verifiers_majority_vote.data[count][count2]+strlen(current_block_verifiers_majority_vote.data[count][count2]),VRF_data.block_verifiers_vrf_secret_key_data[count2],VRF_SECRET_KEY_LENGTH);
    memcpy(current_block_verifiers_majority_vote.data[count][count2]+strlen(current_block_verifiers_majority_vote.data[count][count2]),VRF_data.block_verifiers_vrf_public_key_data[count2],VRF_PUBLIC_KEY_LENGTH);
    memcpy(current_block_verifiers_majority_vote.data[count][count2]+strlen(current_block_verifiers_majority_vote.data[count][count2]),VRF_data.block_verifiers_random_data[count2],RANDOM_STRING_LENGTH);
  }

  return;
}



/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_calculate_vote_majority_results
Description: The block verifiers will calculate the vote majority results
Parameters:
  SETTINGS - The data settings
Return: The valid individual majority count, 1 if a networking error, or 0 if there is not a valid individual majority count
-----------------------------------------------------------------------------------------------------------
*/

int block_verifiers_calculate_vote_majority_results(const int SETTINGS)
{
  // variables
  char data[SMALL_BUFFER_SIZE];
  char data2[SMALL_BUFFER_SIZE];
  unsigned char data3[SMALL_BUFFER_SIZE];
  int count;
  int count2;
  int count3;
  int data_count_1;
  int data_count_2;
  int database_count;
  int majority_settings;
  int majority_count;

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));

  /*
  compare each data that was received for a specific block verifier, for each block verifier
  if a specific majority data can be reached for an specific block verifier, than all block verifiers will go with that response, else they will all go with empty string response
  This will check for an individual majority, and check if any block verifiers did not receive an individual majority from a specific block verifier from a networking issue
  This will also check if a block verifier sent different data to different block verifiers
  */

  // get the majority data hash for each block verifier
  for (database_count = 0, majority_count = 0; database_count < BLOCK_VERIFIERS_AMOUNT; database_count++, majority_settings = 0)
  {
    for (count2 = 0; count2 < BLOCK_VERIFIERS_AMOUNT; count2++)
    {
      for (count = 0, count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++)
      {
        if (strncmp(current_block_verifiers_majority_vote.data[count2][database_count],current_block_verifiers_majority_vote.data[count3][database_count],BUFFER_SIZE) == 0)
        {
          count++;
        }
      }
      if (count >= BLOCK_VERIFIERS_VALID_AMOUNT)
      {
        // the majority data has been found for the specific block verifier
        majority_settings = 1;
        majority_count++;

        if (SETTINGS == 0)
        {
          // reset the VRF data
          memset(VRF_data.block_verifiers_vrf_secret_key_data[database_count],0,strlen(VRF_data.block_verifiers_vrf_secret_key_data[database_count]));
          memset(VRF_data.block_verifiers_vrf_secret_key[database_count],0,strlen((char*)VRF_data.block_verifiers_vrf_secret_key[database_count]));
          memset(VRF_data.block_verifiers_vrf_public_key_data[database_count],0,strlen(VRF_data.block_verifiers_vrf_public_key_data[database_count]));
          memset(VRF_data.block_verifiers_vrf_public_key[database_count],0,strlen((char*)VRF_data.block_verifiers_vrf_public_key[database_count]));
          memset(VRF_data.block_verifiers_random_data[database_count],0,strlen(VRF_data.block_verifiers_random_data[database_count]));

          if (strncmp(current_block_verifiers_majority_vote.data[count2][database_count],BLOCK_VERIFIER_MAJORITY_VRF_DATA_TEMPLATE,BUFFER_SIZE) == 0 || strlen(current_block_verifiers_majority_vote.data[count2][database_count]) != (sizeof(BLOCK_VERIFIER_MAJORITY_VRF_DATA_TEMPLATE)-1))
          {
            // The majority is the empty response, so put the default empty responses for each VRF data  
            memcpy(VRF_data.block_verifiers_vrf_secret_key_data[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA)-1);
            memcpy(VRF_data.block_verifiers_vrf_secret_key[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY)-1);
            memcpy(VRF_data.block_verifiers_vrf_public_key_data[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA)-1);
            memcpy(VRF_data.block_verifiers_vrf_public_key[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY)-1);
            memcpy(VRF_data.block_verifiers_random_data[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING)-1);
          }
          else
          {
            // copy the majority for each VRF data                      
            memcpy(VRF_data.block_verifiers_vrf_secret_key_data[database_count],current_block_verifiers_majority_vote.data[count2][database_count],VRF_SECRET_KEY_LENGTH);
            memcpy(VRF_data.block_verifiers_vrf_public_key_data[database_count],&current_block_verifiers_majority_vote.data[count2][database_count][VRF_SECRET_KEY_LENGTH],VRF_PUBLIC_KEY_LENGTH);
            memcpy(VRF_data.block_verifiers_random_data[database_count],&current_block_verifiers_majority_vote.data[count2][database_count][VRF_SECRET_KEY_LENGTH+VRF_PUBLIC_KEY_LENGTH],RANDOM_STRING_LENGTH);

            // convert the hexadecimal string to a string
            memset(data,0,sizeof(data));
            memset(data3,0,sizeof(data3));
            memcpy(data,VRF_data.block_verifiers_vrf_secret_key_data[database_count],VRF_SECRET_KEY_LENGTH);
            for (data_count_1 = 0, data_count_2 = 0; data_count_1 < VRF_SECRET_KEY_LENGTH; data_count_2++, data_count_1 += 2)
            {
              memset(data2,0,sizeof(data2));
              memcpy(data2,&data[data_count_1],2);
              data3[data_count_2] = (unsigned char)strtol(data2, NULL, 16);
            }
            memcpy(VRF_data.block_verifiers_vrf_secret_key[database_count],data3,crypto_vrf_SECRETKEYBYTES);

            // convert the hexadecimal string to a string
            memset(data,0,sizeof(data));
            memset(data3,0,sizeof(data3));
            memcpy(data,VRF_data.block_verifiers_vrf_public_key_data[database_count],VRF_PUBLIC_KEY_LENGTH);
            for (data_count_1 = 0, data_count_2 = 0; data_count_1 < VRF_PUBLIC_KEY_LENGTH; data_count_2++, data_count_1 += 2)
            {
              memset(data2,0,sizeof(data2));
              memcpy(data2,&data[data_count_1],2);
              data3[data_count_2] = (unsigned char)strtol(data2, NULL, 16);
            }
            memcpy(VRF_data.block_verifiers_vrf_public_key[database_count],data3,crypto_vrf_PUBLICKEYBYTES);
          }          
        }
        else
        {
          // reset the block verifiers signature
          memset(VRF_data.block_blob_signature[database_count],0,strlen(VRF_data.block_blob_signature[database_count]));

          if (strncmp(current_block_verifiers_majority_vote.data[count2][database_count],BLOCK_VERIFIER_MAJORITY_BLOCK_VERIFIERS_SIGNATURE_TEMPLATE,BUFFER_SIZE) == 0 || strlen(current_block_verifiers_majority_vote.data[count2][database_count]) != (sizeof(BLOCK_VERIFIER_MAJORITY_BLOCK_VERIFIERS_SIGNATURE_TEMPLATE)-1))
          {
            // The majority is the empty response, so put the default empty responses for each VRF data  
            memcpy(VRF_data.block_blob_signature[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE)-1);
          }
          else
          {
            // copy the majority for each VRF data                      
            memcpy(VRF_data.block_blob_signature[database_count],current_block_verifiers_majority_vote.data[count2][database_count],VRF_PROOF_LENGTH+VRF_BETA_LENGTH);
          }
        }
        break;
      }
    }

    // check if the majority was not found for that specific block verifier
    if (majority_settings == 0)
    {
      if (SETTINGS == 0)
      {
        // reset the VRF data
        memset(VRF_data.block_verifiers_vrf_secret_key_data[database_count],0,strlen(VRF_data.block_verifiers_vrf_secret_key_data[database_count]));
        memset(VRF_data.block_verifiers_vrf_secret_key[database_count],0,strlen((char*)VRF_data.block_verifiers_vrf_secret_key[database_count]));
        memset(VRF_data.block_verifiers_vrf_public_key_data[database_count],0,strlen(VRF_data.block_verifiers_vrf_public_key_data[database_count]));
        memset(VRF_data.block_verifiers_vrf_public_key[database_count],0,strlen((char*)VRF_data.block_verifiers_vrf_public_key[database_count]));
        memset(VRF_data.block_verifiers_random_data[database_count],0,strlen(VRF_data.block_verifiers_random_data[database_count]));
        memcpy(VRF_data.block_verifiers_vrf_secret_key_data[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA)-1);
        memcpy(VRF_data.block_verifiers_vrf_secret_key[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY)-1);
        memcpy(VRF_data.block_verifiers_vrf_public_key_data[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA)-1);
        memcpy(VRF_data.block_verifiers_vrf_public_key[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY)-1);
        memcpy(VRF_data.block_verifiers_random_data[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING)-1);
      }
      else
      {
        // reset the block verifiers signature
        memset(VRF_data.block_blob_signature[database_count],0,strlen(VRF_data.block_blob_signature[database_count]));
        memcpy(VRF_data.block_blob_signature[database_count],GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE,sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE)-1);
      }
      fprintf(stderr,"\033[1;31m%s does not have a majority data. This block verifier is not working correctly\033[0m\n\n",current_block_verifiers_list.block_verifiers_name[database_count]);
    }
  }

  // check if there was enough specific block verifier majorities
  return majority_count >= BLOCK_VERIFIERS_VALID_AMOUNT ? majority_count : majority_count == 1 ? 1 : 0;
}



/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_create_vote_results
Description: The block verifiers will create the vote results
Parameters:
  message - The message to send to the block verifiers
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int block_verifiers_create_vote_results(char* message)
{
  // Variables
  char data[BUFFER_SIZE];
  char data2[SMALL_BUFFER_SIZE];
  char data3[SMALL_BUFFER_SIZE];
  size_t count;
  size_t count2;

  // define macros
  #define BLOCK_VERIFIERS_CREATE_VOTE_RESULTS_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"block_verifiers_create_vote_results",35); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  return 0; 

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));

  INFO_STAGE_PRINT("Part 21 - Verify the block verifiers from the previous block signatures are valid");

  // verify the block
  if (verify_network_block_data(1,1,"0",BLOCK_VERIFIERS_AMOUNT) == 0)
  {
    BLOCK_VERIFIERS_CREATE_VOTE_RESULTS_ERROR("The MAIN_NODES_TO_NODES_PART_4_OF_ROUND message is invalid");
  }

  INFO_STAGE_PRINT("Part 22 - Create the overall majority data for the reserve bytes (block template with VRF data)");

  // convert the blockchain_data to a network_block_string
  memset(data,0,sizeof(data));	
  if (blockchain_data_to_network_block_string(data,BLOCK_VERIFIERS_AMOUNT) == 0)	
  {		 
    BLOCK_VERIFIERS_CREATE_VOTE_RESULTS_ERROR("Could not convert the blockchain_data to a network_block_string");	
  }
  
  memset(VRF_data.block_blob,0,strlen(VRF_data.block_blob));
  memcpy(VRF_data.block_blob,data,strnlen(data,BUFFER_SIZE));

  // get the data hash of the network block string
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));
  crypto_hash_sha512((unsigned char*)data2,(const unsigned char*)data,(unsigned long long)strnlen(data,BUFFER_SIZE));

  // convert the SHA512 data hash to a string
  for (count2 = 0, count = 0; count2 < DATA_HASH_LENGTH / 2; count2++, count += 2)
  {
    snprintf(data3+count,MAXIMUM_NUMBER_SIZE,"%02x",data2[count2] & 0xFF);
  }

  // reset the current_round_part_vote_data.vote_results_valid struct
  memset(current_round_part_vote_data.current_vote_results,0,sizeof(current_round_part_vote_data.current_vote_results));
  current_round_part_vote_data.vote_results_valid = 1;
  current_round_part_vote_data.vote_results_invalid = 0;

  memcpy(current_round_part_vote_data.current_vote_results,data3,DATA_HASH_LENGTH);

  // create the message
  memset(message,0,strlen(message));
  memcpy(message,"{\r\n \"message_settings\": \"NODES_TO_NODES_VOTE_RESULTS\",\r\n \"vote_settings\": \"valid\",\r\n \"vote_data\": \"",99);  
  memcpy(message+strlen(message),current_round_part_vote_data.current_vote_results,DATA_HASH_LENGTH);
  memcpy(message+strlen(message),"\",\r\n}",5); 
  return 1;

  #undef BLOCK_VERIFIERS_CREATE_VOTE_RESULTS_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_create_block_and_update_database
Description: The block verifiers will create the vote results
Parameters:
  message - The message to send to the block verifiers
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int block_verifiers_create_block_and_update_database(void)
{
  // Variables
  char data[BUFFER_SIZE];
  char data2[BUFFER_SIZE];
  char data3[BUFFER_SIZE];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  size_t count;
  size_t block_height;
  // time_t current_time = time(NULL);

  // threads
  pthread_t thread_id;

  // define macros
  #define BLOCK_VERIFIERS_CREATE_BLOCK_TIMEOUT_SETTINGS 5 // The time to wait to check if the block was created
  #define BLOCK_VERIFIERS_CREATE_BLOCK_AND_UPDATE_DATABASES_ERROR(settings) \
  memcpy(error_message.function[error_message.total],"block_verifiers_create_block_and_update_database",48); \
  memcpy(error_message.data[error_message.total],settings,sizeof(settings)-1); \
  error_message.total++; \
  return 0; 

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));




  // add the seed nodes to the database if their not there, and remove all block heights from the delegates database. only run this for the first five hours to ensure it gets run
  // if (current_time > TIME_SF_V_1_0_6 && current_time < (TIME_SF_V_1_0_6 + (BLOCK_TIME * 60 * 12 * 5)))
  // {
  //   WARNING_PRINT("Shit should not happened. Adding any missing seed nodes to the delegates database");

  //   memcpy(data2,"{\"public_address\":\"",19);
  //   memcpy(data2+19,NETWORK_DATA_NODE_1_PUBLIC_ADDRESS_PRODUCTION,XCASH_WALLET_LENGTH);
  //   memcpy(data2+strlen(data2),"\"}",2);
  //   if (count_documents_in_collection(database_name,"delegates",data2) == 0)
  //   { 
  //     insert_document_into_collection_json(database_name,"delegates",DATABASE_COLLECTION_DELEGATES_DATA_1_PRODUCTION);
  //   }
  //   memset(data2,0,sizeof(data2));

  //   memcpy(data2,"{\"public_address\":\"",19);
  //   memcpy(data2+19,NETWORK_DATA_NODE_2_PUBLIC_ADDRESS_PRODUCTION,XCASH_WALLET_LENGTH);
  //   memcpy(data2+strlen(data2),"\"}",2);
  //   if (count_documents_in_collection(database_name,"delegates",data2) == 0)
  //   { 
  //     insert_document_into_collection_json(database_name,"delegates",DATABASE_COLLECTION_DELEGATES_DATA_2_PRODUCTION);
  //   }
  //   memset(data2,0,sizeof(data2));

  //   memcpy(data2,"{\"public_address\":\"",19);
  //   memcpy(data2+19,NETWORK_DATA_NODE_3_PUBLIC_ADDRESS_PRODUCTION,XCASH_WALLET_LENGTH);
  //   memcpy(data2+strlen(data2),"\"}",2);
  //   if (count_documents_in_collection(database_name,"delegates",data2) == 0)
  //   { 
  //     insert_document_into_collection_json(database_name,"delegates",DATABASE_COLLECTION_DELEGATES_DATA_3_PRODUCTION);
  //   }
  //   memset(data2,0,sizeof(data2));

  //   memcpy(data2,"{\"public_address\":\"",19);
  //   memcpy(data2+19,NETWORK_DATA_NODE_4_PUBLIC_ADDRESS_PRODUCTION,XCASH_WALLET_LENGTH);
  //   memcpy(data2+strlen(data2),"\"}",2);
  //   if (count_documents_in_collection(database_name,"delegates",data2) == 0)
  //   { 
  //     insert_document_into_collection_json(database_name,"delegates",DATABASE_COLLECTION_DELEGATES_DATA_4_PRODUCTION);
  //   }
  //   memset(data2,0,sizeof(data2));

  //   memcpy(data2,"{\"public_address\":\"",19);
  //   memcpy(data2+19,NETWORK_DATA_NODE_5_PUBLIC_ADDRESS_PRODUCTION,XCASH_WALLET_LENGTH);
  //   memcpy(data2+strlen(data2),"\"}",2);
  //   if (count_documents_in_collection(database_name,"delegates",data2) == 0)
  //   { 
  //     insert_document_into_collection_json(database_name,"delegates",DATABASE_COLLECTION_DELEGATES_DATA_5_PRODUCTION);
  //   }
  //   memset(data2,0,sizeof(data2));
  //   memset(data,0,sizeof(data));

  //   // remove block heights from delegates db
  //   remove_block_heights_from_delegates();
  // }

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));






  // add the data hash to the network block string
  INFO_STAGE_PRINT("Part 26 - Add the data hash of the reserve bytes to the block");

  if (add_data_hash_to_network_block_string(VRF_data.block_blob,data) == 0)
  {
    BLOCK_VERIFIERS_CREATE_BLOCK_AND_UPDATE_DATABASES_ERROR("Could not add the data hash of the reserve bytes to the block");
  }

  INFO_PRINT_STATUS_OK("Added the data hash of the reserve bytes to the block");

  INFO_STAGE_PRINT("Part 27 - Add the reserve bytes to the database");
    


  // update the reserve bytes database

  get_reserve_bytes_database(count,0); 

  memset(data2,0,sizeof(data2));
  memcpy(data2,"{\"block_height\":\"",17);
  memcpy(data2+17,current_block_height,strnlen(current_block_height,sizeof(current_block_height)));
  memcpy(data2+strlen(data2),"\",\"reserve_bytes_data_hash\":\"",29);
  memcpy(data2+strlen(data2),VRF_data.reserve_bytes_data_hash,DATA_HASH_LENGTH);
  memcpy(data2+strlen(data2),"\",\"reserve_bytes\":\"",19);
  memcpy(data2+strlen(data2),VRF_data.block_blob,strnlen(VRF_data.block_blob,sizeof(data2)));
  memcpy(data2+strlen(data2),"\"}",2);

  // add the network block string to the database
  memcpy(data3,"reserve_bytes_",14);
  snprintf(data3+14,MAXIMUM_NUMBER_SIZE,"%zu",count);
  // FIXME replace to upsert function

  if (upsert_json_to_db(database_name,XCASH_DB_RESERVE_BYTES, count, data2, false) == XCASH_ERROR){
    ERROR_PRINT("Could not add the reserve bytes to the database");
    return XCASH_ERROR;
  };


  // if (insert_document_into_collection_json(database_name,data3,data2) == 0)
  // {
  //   BLOCK_VERIFIERS_CREATE_BLOCK_AND_UPDATE_DATABASES_ERROR("Could not add the reserve bytes to the database");
  // }

  INFO_PRINT_STATUS_OK("Added the reserve bytes to the database");
  
  if (strncmp(current_round_part_backup_node,"0",1) == 0)
  {

    sscanf(current_block_height,"%zu", &block_height);

    // get the current date and time
    get_current_UTC_time(current_date_and_time,current_UTC_date_and_time);
    if (block_height >= BLOCK_HEIGHT_SF_V_1_0_1 && current_UTC_date_and_time.tm_min > 30 && current_UTC_date_and_time.tm_min < 35)
    {
      // start the reserve proofs delegate check
      INFO_STAGE_PRINT("Part 28 - Starting the reserve proofs delegate check");
      reserve_proofs_delegate_check();
      INFO_PRINT_STATUS_OK("The reserve proofs delegate check is finished");
    }
    else
    {
      // start the reserve proofs timer
      INFO_STAGE_PRINT("Part 28 - Check for invalid reserve proofs and wait for the block producer to submit the block to the network");
      pthread_create(&thread_id, NULL, &check_reserve_proofs_timer_thread, NULL);
      pthread_detach(thread_id);
    }
  }

  if (sync_block_verifiers_minutes_and_seconds((BLOCK_TIME -1),0) == XCASH_ERROR){
      return XCASH_ERROR;
  }


  // sync_block_verifiers_minutes_and_seconds((BLOCK_TIME-1),SUBMIT_NETWORK_BLOCK_TIME_SECONDS);

  // let the block producer try to submit the block first, then loop through all of the network data nodes to make sure it was submitted
  if ((strncmp(current_round_part_backup_node, "0", 1) == 0 &&
       strncmp(main_nodes_list.block_producer_public_address, xcash_wallet_public_address, XCASH_WALLET_LENGTH) == 0) ||
      (strncmp(current_round_part_backup_node, "1", 1) == 0 &&
       strncmp(main_nodes_list.block_producer_backup_block_verifier_1_public_address, xcash_wallet_public_address,
               XCASH_WALLET_LENGTH) == 0) ||
      (strncmp(current_round_part_backup_node, "2", 1) == 0 &&
       strncmp(main_nodes_list.block_producer_backup_block_verifier_2_public_address, xcash_wallet_public_address,
               XCASH_WALLET_LENGTH) == 0) ||
      (strncmp(current_round_part_backup_node, "3", 1) == 0 &&
       strncmp(main_nodes_list.block_producer_backup_block_verifier_3_public_address, xcash_wallet_public_address,
               XCASH_WALLET_LENGTH) == 0) ||
      (strncmp(current_round_part_backup_node, "4", 1) == 0 &&
       strncmp(main_nodes_list.block_producer_backup_block_verifier_4_public_address, xcash_wallet_public_address,
               XCASH_WALLET_LENGTH) == 0) ||
      (strncmp(current_round_part_backup_node, "5", 1) == 0 &&
       strncmp(main_nodes_list.block_producer_backup_block_verifier_5_public_address, xcash_wallet_public_address,
               XCASH_WALLET_LENGTH) == 0)) {
      INFO_STAGE_PRINT("Sending the new block to blockchain");

      if (submit_block_template(data)!= XCASH_OK) {
        WARNING_PRINT("Sending the new block to blockchain returned error");
      }else{
        INFO_PRINT_STATUS_OK("New block sent to blockchain successfully");
      }
  }
  sleep(BLOCK_VERIFIERS_SETTINGS);

  // TODO there is a place where we're related on SEED nodes to store created block

  // if we're the seed node, we store block on our side
  for (count = 0; count < NETWORK_DATA_NODES_AMOUNT; count++)
  {
    if (strncmp(network_data_nodes_list.network_data_nodes_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0)
    {
      INFO_STAGE_PRINT("Sending the new block to blockchain");
      if (submit_block_template(data)!= XCASH_OK) {
        WARNING_PRINT("Sending the new block to blockchain returned error");
      }else{
        INFO_PRINT_STATUS_OK("New block sent to blockchain successfully");
      }
    }
  }


  INFO_STAGE_PRINT("Waiting for block propagation...");
  sync_block_verifiers_minutes_and_seconds((BLOCK_TIME -1),40);

  return XCASH_OK;

  #undef BLOCK_VERIFIERS_CREATE_BLOCK_TIMEOUT_SETTINGS
  #undef BLOCK_VERIFIERS_CREATE_BLOCK_AND_UPDATE_DATABASES_ERROR
}



/*
-----------------------------------------------------------------------------------------------------------
Name: print_block_producer
Description: Prints the block producers name
-----------------------------------------------------------------------------------------------------------
*/

void print_block_producer(void)
{
  // Variables
  int count;


  fprintf(stderr,"Selected block producer:\nRound %c\n",current_round_part_backup_node[0]);
  fprintf(stderr,"Main producer: %s\n",main_nodes_list.block_producer_public_address);
  fprintf(stderr,"Backup1 producer: %s\n",main_nodes_list.block_producer_backup_block_verifier_1_public_address);
  fprintf(stderr,"Backup2 producer: %s\n",main_nodes_list.block_producer_backup_block_verifier_2_public_address);
  fprintf(stderr,"Backup3 producer: %s\n",main_nodes_list.block_producer_backup_block_verifier_3_public_address);
  fprintf(stderr,"Backup4 producer: %s\n",main_nodes_list.block_producer_backup_block_verifier_4_public_address);
  fprintf(stderr,"Backup5 producer: %s\n",main_nodes_list.block_producer_backup_block_verifier_5_public_address);
  if (strncmp(current_round_part_backup_node,"0",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_public_address,BUFFER_SIZE) == 0)
      {
        fprintf(stderr,"\033[1;36m%s is the block producer\033[0m\n\n",current_block_verifiers_list.block_verifiers_name[count]);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"1",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_1_public_address,BUFFER_SIZE) == 0)
      {
        fprintf(stderr,"\033[1;36m%s is the block producer\033[0m\n\n",current_block_verifiers_list.block_verifiers_name[count]);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"2",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_2_public_address,BUFFER_SIZE) == 0)
      {
        fprintf(stderr,"\033[1;36m%s is the block producer\033[0m\n\n",current_block_verifiers_list.block_verifiers_name[count]);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"3",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_3_public_address,BUFFER_SIZE) == 0)
      {
        fprintf(stderr,"\033[1;36m%s is the block producer\033[0m\n\n",current_block_verifiers_list.block_verifiers_name[count]);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"4",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_4_public_address,BUFFER_SIZE) == 0)
      {
        fprintf(stderr,"\033[1;36m%s is the block producer\033[0m\n\n",current_block_verifiers_list.block_verifiers_name[count]);
        break;
      }
    }
  }
  else if (strncmp(current_round_part_backup_node,"5",1) == 0)
  {
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],main_nodes_list.block_producer_backup_block_verifier_5_public_address,BUFFER_SIZE) == 0)
      {
        fprintf(stderr,"\033[1;36m%s is the block producer\033[0m\n\n",current_block_verifiers_list.block_verifiers_name[count]);
        break;
      }
    }
  }
  return;
}


// bool select_block_producers_majority(response_t *replies) {
//   bool result = false;


//   return result;
// }


/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_create_block
Description: Runs the round where the block verifiers will create the block
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int block_verifiers_create_block(size_t round_number) {
    // Variables
    char data[BUFFER_SIZE];
    char data2[BUFFER_SIZE];
    // time_t current_date_and_time;
    // struct tm current_UTC_date_and_time;
    size_t count;
    size_t count2;
    int count3;

    response_t** replies = NULL;

    current_round_part[0] = '1';
    current_round_part_backup_node[0] = (char)('0'+round_number);


    for (count = 0; count < 50; count++) {
        memset(VRF_data.block_verifiers_vrf_secret_key_data[count], 0, VRF_SECRET_KEY_LENGTH + 1);
        memset(VRF_data.block_verifiers_vrf_secret_key[count], 0, crypto_vrf_SECRETKEYBYTES + 1);
        memset(VRF_data.block_verifiers_vrf_public_key_data[count], 0, VRF_PUBLIC_KEY_LENGTH + 1);
        memset(VRF_data.block_verifiers_vrf_public_key[count], 0, crypto_vrf_PUBLICKEYBYTES + 1);
        memset(VRF_data.block_verifiers_random_data[count], 0, RANDOM_STRING_LENGTH + 1);
        memset(VRF_data.block_blob_signature[count], 0, VRF_PROOF_LENGTH + VRF_BETA_LENGTH + 1);
    }

    memset(VRF_data.vrf_secret_key_data, 0, BUFFER_SIZE_NETWORK_BLOCK_DATA);
    memset(VRF_data.vrf_secret_key, 0, BUFFER_SIZE_NETWORK_BLOCK_DATA);
    memset(VRF_data.vrf_public_key_data, 0, BUFFER_SIZE_NETWORK_BLOCK_DATA);
    memset(VRF_data.vrf_public_key, 0, BUFFER_SIZE_NETWORK_BLOCK_DATA);

    memset(VRF_data.vrf_alpha_string_data, 0, BUFFER_SIZE);
    memset(VRF_data.vrf_alpha_string, 0, BUFFER_SIZE);

    memset(VRF_data.vrf_proof_data, 0, BUFFER_SIZE_NETWORK_BLOCK_DATA);
    memset(VRF_data.vrf_proof, 0, BUFFER_SIZE_NETWORK_BLOCK_DATA);
    memset(VRF_data.vrf_beta_string_data, 0, BUFFER_SIZE_NETWORK_BLOCK_DATA);
    memset(VRF_data.vrf_beta_string, 0, BUFFER_SIZE_NETWORK_BLOCK_DATA);
    
    memset(VRF_data.block_blob, 0, BUFFER_SIZE);
    memset(VRF_data.reserve_bytes_data_hash, 0, DATA_HASH_LENGTH + 1);


    // cleaning here solves the bug with concurency problem during messages exchange
    memset(&current_block_verifiers_majority_vote, 0, sizeof(current_block_verifiers_majority_vote));

    memset(data, 0, sizeof(data));
    memset(data2, 0, sizeof(data2));

    // set the main_network_data_node_create_block so the main network data node can create the block
    main_network_data_node_create_block = 0;

    // wait for all block verifiers to sync

    INFO_STAGE_PRINT("Waiting for block syncronization start time...");


    if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
        if (sync_block_verifiers_minutes_and_seconds(0, 30) == XCASH_ERROR) {
            return ROUND_NEXT;
        }
    } else {
        if (sync_block_verifiers_minutes_and_seconds(3, 5) == XCASH_ERROR) {
            return ROUND_SKIP;
        }
    }

    // INFO_STAGE_PRINT("Part 0 - Exchanging block producers list");

    // replies = NULL;
    // if (!send_message(XNET_DELEGATES_ALL_ONLINE,XMSG_XCASH_GET_BLOCK_PRODUCERS, &replies)){
    //     WARNING_PRINT("Error during XCASH_GET_BLOCK_PRODUCERS request");
    //     cleanup_responses(replies);
    //     return ROUND_NEXT;
    // }
    
    // if (!select_block_producers_majority(replies)) {
    //     WARNING_PRINT("Can't select block producer");
    //     cleanup_responses(replies);
    //     return ROUND_NEXT;
    // }
    // cleanup_responses(replies);

    // size_t round_number = current_round_part_backup_node[0] - '0';
    // show_block_producer(round_number);

    // INFO_PRINT_STATUS_OK("Block producer selected");


    // if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
    //     if (sync_block_verifiers_minutes_and_seconds(0, 40) == XCASH_ERROR) {
    //         return ROUND_NEXT;
    //     }
    // } else {
    //     if (sync_block_verifiers_minutes_and_seconds(3, 10) == XCASH_ERROR) {
    //         return ROUND_SKIP;
    //     }
    // }

    // check if this is a false postive replayed round and sit out the round, this way the block verifier does not
    // remove a valid blocks data from the database
    if (get_current_block_height(data) == 1 && strncmp(current_block_height, data, BUFFER_SIZE) != 0) {
        WARNING_PRINT("Your block height is not synced correctly, waiting for the next round to begin");
        replayed_round_settings = 1;
        return ROUND_NEXT;
    }

    memset(data, 0, sizeof(data));

    if (get_previous_block_hash(previous_block_hash) == 0) {
        WARNING_PRINT("Could not get the previous block hash");
        return ROUND_NEXT;
    }

// start:
    // FIXME move the round restart logic to upper level function

    INFO_STAGE_PRINT("Part 1 - Create VRF data");

    //! 1. exchange VRF keys between nodes
    //! fix. get_vrf_keys set block_height and round_number so the server distribute the same keys
    //!!!! THINK!!! there can be concurrency problem if server receives key request before we make it
    //! maybe better not to send, but just get. generate keys on server side and control by mutex
    // create a random VRF public key and secret key
    if (block_verifiers_create_VRF_secret_key_and_VRF_public_key(data) == 0) {
        WARNING_PRINT("Could not create VRF data");
        return ROUND_NEXT;
    }

    // sign_data
    if (sign_data(data) == 0) {
        WARNING_PRINT("Could not create VRF data");
        return ROUND_NEXT;
    }

    INFO_PRINT_STATUS_OK("The VRF data has been created");

    INFO_STAGE_PRINT("Part 2 - Send VRF data to all block verifiers");

    // send the message to all block verifiers

    replies = NULL;
    if (!xnet_send_data_multi(XNET_DELEGATES_ALL_ONLINE, (const char*)data, &replies)) {
        WARNING_PRINT("Could not send VRF data to all block verifiers");
        cleanup_responses(replies);
        return ROUND_NEXT;
    }
    cleanup_responses(replies);

    // if (block_verifiers_send_data_socket((const char*)data) == 0)
    // {
    //   RESTART_ROUND("Could not send VRF data to all block verifiers");
    // }

    INFO_PRINT_STATUS_OK("The VRF data has been sent to all block verifiers");

    INFO_STAGE_PRINT("Part 3 - Wait for all block verifiers to receive the VRF data");

    if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
        if (sync_block_verifiers_minutes_and_seconds(1, 10) == XCASH_ERROR) {
            return ROUND_NEXT;
        }
    } else {
        if (sync_block_verifiers_minutes_and_seconds(3, 15) == XCASH_ERROR) {
            return ROUND_SKIP;
        }
    }
    // strncmp(current_round_part_backup_node,"0",1) == 0 ? sync_block_verifiers_minutes_and_seconds(2,0) :
    // sync_block_verifiers_minutes_and_seconds(3,15);

    //! At this point we're collected all VRF keys from all block verifiers
    //! now send all VRF keys to each delegates in 'active' (top 50) list

    // create each individual majority VRF data
    INFO_STAGE_PRINT("Part 4 - Create each individual majority VRF data");
    memset(data, 0, sizeof(data));
    block_verifiers_create_vote_majority_results(data, 0);

    // sign_data
    if (sign_data(data) == 0) {
        WARNING_PRINT("Could not create each individual majority VRF data");
        return ROUND_NEXT;
    }

    INFO_PRINT_STATUS_OK("Each individual majority VRF data has been created");

    INFO_STAGE_PRINT("Part 5 - Send each individual majority VRF data to all block verifiers");

    // send the message to all block verifiers

    replies = NULL;
    if (!xnet_send_data_multi(XNET_DELEGATES_ALL_ONLINE, (const char*)data, &replies)) {
        WARNING_PRINT("Could not send each individual majority VRF data to all block verifiers");
        cleanup_responses(replies);
        return ROUND_NEXT;
    }
    cleanup_responses(replies);

    // if (block_verifiers_send_data_socket((const char*)data) == 0)
    // {
    //   RESTART_ROUND("Could not send each individual majority VRF data to all block verifiers");
    // }

    INFO_PRINT_STATUS_OK("Each individual majority VRF data has been sent to all block verifiers");

    INFO_STAGE_PRINT("Part 6 - Wait for all block verifiers to receive each individual majority VRF data");

    if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
        if (sync_block_verifiers_minutes_and_seconds(1, 25) == XCASH_ERROR) {
            return ROUND_NEXT;
        }
    } else {
        if (sync_block_verifiers_minutes_and_seconds(3, 25) == XCASH_ERROR) {
            return ROUND_SKIP;
        }
    }

    // strncmp(current_round_part_backup_node,"0",1) == 0 ? sync_block_verifiers_minutes_and_seconds(2,10) :
    // sync_block_verifiers_minutes_and_seconds(3,25);

    

    size_t majority[BLOCK_VERIFIERS_AMOUNT];
    memset(majority, 0 , sizeof(majority));

    for (size_t i = 0; i < BLOCK_VERIFIERS_AMOUNT; i++)
    {
      for (size_t j = 0; j < BLOCK_VERIFIERS_AMOUNT; j++)
      {
        if ((strlen(current_block_verifiers_majority_vote.data[i][j]) != 0) && (strcmp(current_block_verifiers_majority_vote.data[i][j],BLOCK_VERIFIER_MAJORITY_VRF_DATA_TEMPLATE) != 0)) {
          majority[j]++;
        }
      }      
    }
    
    INFO_STAGE_PRINT("Round %s Final participants", current_round_part_backup_node);

    for (size_t i = 0; i < BLOCK_VERIFIERS_AMOUNT; i++) {
      if ((majority[i] >= BLOCK_VERIFIERS_VALID_AMOUNT) && (strcmp(delegates_all[i].online_status, "true")==0))
      {
          strcpy(delegates_all[i].online_status, "true");
          INFO_PRINT_STATUS_OK("[%02ld] %s",majority[i], current_block_verifiers_list.block_verifiers_name[i]);
      } else {
        if ((strlen(delegates_all[i].online_status)==0) && (majority[i] >0)) {
          INFO_PRINT_STATUS_FAIL("[%02ld] %s (wrong client version)",majority[i], current_block_verifiers_list.block_verifiers_name[i]);
        }else if (majority[i] >0) {
          INFO_PRINT_STATUS_FAIL("[%02ld] %s",majority[i], current_block_verifiers_list.block_verifiers_name[i]);
        }

        if (strlen(delegates_all[i].online_status)>0) {
          strcpy(delegates_all[i].online_status, "false");
        }

      }
    }

    select_block_producers(round_number);

    INFO_PRINT_STATUS_OK("Block producer selected");
    show_block_producer(round_number);


    //! wtf??? why not checking majority here

    // check each specific block verifier to see if they have a majority
    INFO_STAGE_PRINT("Part 7 - Check each specific block verifier to see if they have a majority for the VRF data");

    // count = (size_t)block_verifiers_calculate_vote_majority_results(0);

    // temporary fix
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) {
        if (strlen(VRF_data.block_verifiers_vrf_secret_key_data[count]) == 0 ||
            strlen((char*)VRF_data.block_verifiers_vrf_secret_key[count]) == 0 ||
            strlen(VRF_data.block_verifiers_vrf_public_key_data[count]) == 0 ||
            strlen((char*)VRF_data.block_verifiers_vrf_public_key[count]) == 0 ||
            strlen(VRF_data.block_verifiers_random_data[count]) == 0) {
            // The majority is the empty response, so put the default empty responses for each VRF data
            memcpy(VRF_data.block_verifiers_vrf_secret_key_data[count],
                   GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA,
                   sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA) - 1);
            memcpy(VRF_data.block_verifiers_vrf_secret_key[count], GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY,
                   sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY) - 1);
            memcpy(VRF_data.block_verifiers_vrf_public_key_data[count],
                   GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA,
                   sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA) - 1);
            memcpy(VRF_data.block_verifiers_vrf_public_key[count], GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY,
                   sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY) - 1);
            memcpy(VRF_data.block_verifiers_random_data[count], GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,
                   sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING) - 1);
        }
    }
    count = BLOCK_VERIFIERS_AMOUNT;
    // temporary fix

    INFO_PRINT_STATUS_OK("Checked each specific block verifier to see if they have a majority for the VRF data");

    INFO_STAGE_PRINT("Part 8 - Check if there was enough specific block verifier majorities for the VRF data");

    //! this always be true because of cheating above with count = BLOCK_VERIFIERS_AMOUNT wft???
    if (count >= BLOCK_VERIFIERS_VALID_AMOUNT) {
        INFO_PRINT_STATUS_OK("[%zu / %d] block verifiers have a specific majority for the VRF data", count, BLOCK_VERIFIERS_VALID_AMOUNT);
    } else
    // !this will never executed because of shit above
    {
        if (count == 0 || count == 1) {
            // check if your delegate is a current block verifier
            for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++) {
                if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count3],
                            xcash_wallet_public_address, XCASH_WALLET_LENGTH) == 0) {
                    break;
                }
            }

            if (count3 != BLOCK_VERIFIERS_AMOUNT) {
                // your delegate is a current block verifier, restart the delegate as it could only verify its own
                // message and not anyone elses message
                WARNING_PRINT("Restarting, could not process any other block verifiers data");
                // ! wtf?
                // FIXME check memory etc
                return ROUND_SKIP;
                // exit(0);
            }
        }
        INFO_PRINT_STATUS_FAIL("[%zu / %d] block verifiers have a specific majority for the VRF data", count, BLOCK_VERIFIERS_VALID_AMOUNT);
        WARNING_PRINT("There was an invalid amount of specific block verifier majorities for the VRF data");
        return ROUND_NEXT;
    }

    INFO_STAGE_PRINT("Part 9 - Check if there was an overall majority for the VRF data");
    RESET_DELEGATE_ERROR_MESSAGE;

    // process the data
    for (count = 0, count2 = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) {
        if (strncmp(VRF_data.block_verifiers_vrf_secret_key_data[count],
                    GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA, BUFFER_SIZE) != 0 &&
            strncmp(VRF_data.block_verifiers_vrf_public_key_data[count],
                    GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA, BUFFER_SIZE) != 0 &&
            strncmp(VRF_data.block_verifiers_random_data[count], GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,
                    BUFFER_SIZE) != 0) {
            count2++;
        } else {
            memcpy(delegates_error_list + strlen(delegates_error_list),
                   current_block_verifiers_list.block_verifiers_name[count],
                   strlen(current_block_verifiers_list.block_verifiers_name[count]));
            memcpy(delegates_error_list + strlen(delegates_error_list), "|", 1);
        }
    }

    // check for what delegates did not send any response for this round
    // if (delegates_error_list_settings == 1 && count2 != BLOCK_VERIFIERS_AMOUNT) {
    //     color_print(delegates_error_list, "red");
    // }

    // check for an overall majority
    if (count2 >= BLOCK_VERIFIERS_VALID_AMOUNT) {
        INFO_PRINT_STATUS_OK("[%zu / %d] block verifiers have an overall majority for the VRF data", count2, BLOCK_VERIFIERS_VALID_AMOUNT);
    } else {
        if (count2 == 0 || count2 == 1) {
            // check if your delegate is a current block verifier
            for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++) {
                if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count3],
                            xcash_wallet_public_address, XCASH_WALLET_LENGTH) == 0) {
                    break;
                }
            }

            if (count3 != BLOCK_VERIFIERS_AMOUNT) {
                // your delegate is a current block verifier, restart the delegate as it could only verify its own
                // message and not anyone elses message
                WARNING_PRINT("Restarting, could not process any other block verifiers data");
                // FIXME check memory etc
                return ROUND_SKIP;

                // exit(0);
            }
        }
        INFO_PRINT_STATUS_FAIL("[%zu / %d] block verifiers have an overall majority for the VRF data", count2, BLOCK_VERIFIERS_VALID_AMOUNT);
        WARNING_PRINT("An invalid amount of block verifiers have an overall majority for the VRF data");
        return ROUND_NEXT;
    }

    // at this point all block verifiers should have the all of the other block verifiers secret key, public key and
    // random data
    INFO_STAGE_PRINT("Part 10 - Select VRF data to use for the round");

    // create all of the VRF data
    if (block_verifiers_create_VRF_data() == 0) {
        WARNING_PRINT("Could not select the VRF data to use for the round");
        return ROUND_NEXT;
    }

    INFO_PRINT_STATUS_OK("VRF data has been selected for the round");



    // INFO_STAGE_PRINT("Round %s Final participants", current_round_part_backup_node);

    // for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) {
    //   if (strncmp(VRF_data.block_verifiers_vrf_secret_key_data[count],
    //               GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_SECRET_KEY_DATA, BUFFER_SIZE) != 0 &&
    //       strncmp(VRF_data.block_verifiers_vrf_public_key_data[count],
    //               GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_VRF_PUBLIC_KEY_DATA, BUFFER_SIZE) != 0 &&
    //       strncmp(VRF_data.block_verifiers_random_data[count], GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_RANDOM_STRING,
    //               BUFFER_SIZE) != 0) 
    //   {
    //       INFO_PRINT_STATUS_OK("%s", current_block_verifiers_list.block_verifiers_name[count]);
    //   }
    // }


    // create the block template and send it to all block verifiers if the block verifier is the block producer
    if (strcmp(producer_refs[round_number].public_address, xcash_wallet_public_address) == 0) {
        INFO_STAGE_PRINT("Part 11 - Create the block template and send it to all block verifiers");

        // ! here we go. get block_template_blob
        if (get_block_template(VRF_data.block_blob) == 0) {
            WARNING_PRINT("Could not create the block template");
            return ROUND_NEXT;
        }

        // create the message
        memset(data, 0, sizeof(data));
        memcpy(data,
               "{\r\n \"message_settings\": \"MAIN_NODES_TO_NODES_PART_4_OF_ROUND_CREATE_NEW_BLOCK\",\r\n "
               "\"block_blob\": \"",
               97);
        memcpy(data + 97, VRF_data.block_blob, strnlen(VRF_data.block_blob, BUFFER_SIZE));
        memcpy(data + strlen(data), "\",\r\n}", 5);

        // sign_data

        if (sign_data(data) == 0) {
            WARNING_PRINT("Could not create the block template");
            return ROUND_NEXT;
        }

        replies = NULL;
        if (!xnet_send_data_multi(XNET_DELEGATES_ALL_ONLINE, (const char*)data, &replies)) {
            WARNING_PRINT("Could not send the block template");
            cleanup_responses(replies);
            return ROUND_NEXT;
        }
        cleanup_responses(replies);

        // if (sign_data(data) == 0 || block_verifiers_send_data_socket((const char*)data) == 0) {
        //     RESTART_ROUND("Could not create the block template");
        // }
    } else {
        INFO_STAGE_PRINT("Part 11 - Wait for all block verifiers to receive the block template from the block producer");
    }

    // wait for the block verifiers to receive the block template from the block producer

    if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
        if (sync_block_verifiers_minutes_and_seconds(2, 20) == XCASH_ERROR) {
            return ROUND_NEXT;
        }
    } else {
        if (sync_block_verifiers_minutes_and_seconds(3, 35) == XCASH_ERROR) {
            return ROUND_SKIP;
        }
    }

    // strncmp(current_round_part_backup_node,"0",1) == 0 ? sync_block_verifiers_minutes_and_seconds(2,20) :
    // sync_block_verifiers_minutes_and_seconds(3,35);

    // check if the network block string was created from the correct block verifier
    if (strncmp(VRF_data.block_blob, "", 1) == 0) {
        WARNING_PRINT("Could not receive the block template from the block producer");
        return ROUND_NEXT;
    }

    INFO_PRINT_STATUS_OK("Received the block template from the block producer");

    // at this point all block verifiers should have the same VRF data and the network block
    INFO_STAGE_PRINT("Part 12 - Add the VRF data to the block template and sign the block template");

    // create the block verifiers block signature
    if (block_verifiers_create_block_signature(data) == 0 || sign_data(data) == 0) {
        WARNING_PRINT("Could not add the VRF data to the block template and sign the block template");
        return ROUND_NEXT;
    }

    INFO_PRINT_STATUS_OK("Added the VRF data to the block template and signed the block template");

    INFO_STAGE_PRINT("Part 13 - Send the block template signature to all block verifier");

    // send the message to all block verifiers

    replies = NULL;
    if (!xnet_send_data_multi(XNET_DELEGATES_ALL_ONLINE, (const char*)data, &replies)) {
        WARNING_PRINT("Could not send the block template signature to all block verifier");
        cleanup_responses(replies);
        return ROUND_NEXT;
    }
    cleanup_responses(replies);

    // if (block_verifiers_send_data_socket((const char*)data) == 0)
    // {
    //   RESTART_ROUND("Could not send the block template signature to all block verifier");
    // }

    INFO_PRINT_STATUS_OK("Sent the block template signature to all block verifiers");

    INFO_STAGE_PRINT("Part 14 - Wait for all block verifiers to receive the block template signatures");

    if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
        if (sync_block_verifiers_minutes_and_seconds(2, 30) == XCASH_ERROR) {
            return ROUND_NEXT;
        }
    } else {
        if (sync_block_verifiers_minutes_and_seconds(3, 45) == XCASH_ERROR) {
            return ROUND_SKIP;
        }
    }

    // strncmp(current_round_part_backup_node,"0",1) == 0 ? sync_block_verifiers_minutes_and_seconds(2,30) :
    // sync_block_verifiers_minutes_and_seconds(3,45);

    // create each individual majority block template signature
    INFO_STAGE_PRINT("Part 15 - Create each individual majority block template signature");
    memset(data, 0, sizeof(data));
    block_verifiers_create_vote_majority_results(data, 1);

    // sign_data
    if (sign_data(data) == 0) {
        WARNING_PRINT("Could not create each individual majority block template signature");
        return ROUND_NEXT;
    }

    INFO_PRINT_STATUS_OK("Each individual majority block template signature has been created");

    INFO_STAGE_PRINT("Part 16 - Send each individual majority block template signature to all block verifiers");

    // send the message to all block verifiers

    replies = NULL;
    if (!xnet_send_data_multi(XNET_DELEGATES_ALL_ONLINE, (const char*)data, &replies)) {
        WARNING_PRINT("Could not send each individual majority block template signature to all block verifiers");
        cleanup_responses(replies);
        return ROUND_NEXT;
    }
    cleanup_responses(replies);

    // if (block_verifiers_send_data_socket((const char*)data) == 0)
    // {
    //   RESTART_ROUND("Could not send each individual majority block template signature to all block verifiers");
    // }

    INFO_PRINT_STATUS_OK("Each individual majority block template signature has been sent to all block verifiers");

    INFO_STAGE_PRINT("Part 17 - Wait for all block verifiers to receive each individual majority block template signature");

    if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
        if (sync_block_verifiers_minutes_and_seconds(2, 40) == XCASH_ERROR) {
            return ROUND_NEXT;
        }
    } else {
        if (sync_block_verifiers_minutes_and_seconds(3, 55) == XCASH_ERROR) {
            return ROUND_SKIP;
        }
    }

    // strncmp(current_round_part_backup_node,"0",1) == 0 ? sync_block_verifiers_minutes_and_seconds(2,40) :
    // sync_block_verifiers_minutes_and_seconds(3,55);

    // check each specific block verifier to see if they have a majority
    INFO_STAGE_PRINT("Part 18 - Check each specific block verifier to see if they have a majority for the block template signature");

    // count = (size_t)block_verifiers_calculate_vote_majority_results(1);

    // temporary fix
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) {
        if (strlen(VRF_data.block_blob_signature[count]) == 0) {
            // The majority is the empty response, so put the default empty responses for each VRF data
            memcpy(VRF_data.block_blob_signature[count], GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE,
                   sizeof(GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE) - 1);
        }
    }
    count = BLOCK_VERIFIERS_AMOUNT;
    // temporary fix

    INFO_PRINT_STATUS_OK(
        "Checked each specific block verifier to see if they have a majority for the block template signature");

    INFO_STAGE_PRINT("Part 19 - Check if there was enough specific block verifier majorities for the block template signature");

    // ! the first is alway true because of temporary fix above
    if (count >= BLOCK_VERIFIERS_VALID_AMOUNT) {
        INFO_PRINT_STATUS_OK("[%zu / %d] block verifiers have a specific majority for the block template signature", count, BLOCK_VERIFIERS_VALID_AMOUNT);
    } else {
        if (count == 0 || count == 1) {
            // check if your delegate is a current block verifier
            for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++) {
                if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count3],
                            xcash_wallet_public_address, XCASH_WALLET_LENGTH) == 0) {
                    break;
                }
            }

            if (count3 != BLOCK_VERIFIERS_AMOUNT) {
                // your delegate is a current block verifier, restart the delegate as it could only verify its own
                // message and not anyone elses message
                WARNING_PRINT("Restarting, could not process any other block verifiers data");
                //! wtf??
                // FIXME check memory etc
                return ROUND_SKIP;
                // exit(0);
            }
        }
        INFO_PRINT_STATUS_FAIL("[%zu / %d] block verifiers have a specific majority for the block template signature",count, BLOCK_VERIFIERS_VALID_AMOUNT);
        WARNING_PRINT("There was an invalid amount of specific block verifier majorities for the block template signature");
        return ROUND_NEXT;
    }

    // at this point all block verifiers should have the same VRF data, network block string and all block verifiers
    // signed data

    INFO_STAGE_PRINT("Part 20 - Check if there was an overall majority for the block template signature");
    RESET_DELEGATE_ERROR_MESSAGE;

    // process the data and add the block verifiers signatures to the block
    for (count = 0, count2 = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) {
        if (strncmp(VRF_data.block_blob_signature[count], GET_BLOCK_TEMPLATE_BLOCK_VERIFIERS_SIGNATURE, BUFFER_SIZE) !=
            0) {
            count2++;
        } else {
            memcpy(delegates_error_list + strlen(delegates_error_list),
                   current_block_verifiers_list.block_verifiers_name[count],
                   strlen(current_block_verifiers_list.block_verifiers_name[count]));
            memcpy(delegates_error_list + strlen(delegates_error_list), "|", 1);
        }
    }

    // check for what delegates did not send any response for this round
    // if (delegates_error_list_settings == 1 && count2 != BLOCK_VERIFIERS_AMOUNT) {
    //     color_print(delegates_error_list, "red");
    // }

    // check for an overall majority
    if (count2 >= BLOCK_VERIFIERS_VALID_AMOUNT) {
        INFO_PRINT_STATUS_OK("[%zu / %d] block verifiers have an overall majority for the block template signature",count2, BLOCK_VERIFIERS_VALID_AMOUNT);
    } else {
        if (count2 == 0 || count2 == 1) {
            // check if your delegate is a current block verifier
            for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++) {
                if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count3],
                            xcash_wallet_public_address, XCASH_WALLET_LENGTH) == 0) {
                    break;
                }
            }

            if (count3 != BLOCK_VERIFIERS_AMOUNT) {
                // your delegate is a current block verifier, restart the delegate as it could only verify its own
                // message and not anyone elses message
                WARNING_PRINT("Restarting, could not process any other block verifiers data");
                //! wtf?
                // FIXME check memory etc
                return ROUND_SKIP;

                // exit(0);
            }
        }
        INFO_PRINT_STATUS_FAIL("[%zu / %d] block verifiers have an overall majority for the block template signature",count2, BLOCK_VERIFIERS_VALID_AMOUNT);
        WARNING_PRINT("An invalid amount of block verifiers have an overall majority for the block template signature");
        return ROUND_NEXT;
    }

    // create the vote results
    if (block_verifiers_create_vote_results(data) == 0 || sign_data(data) == 0) {
        WARNING_PRINT("Could not create the overall majority data for the reserve bytes");
        return ROUND_NEXT;
    }

    INFO_PRINT_STATUS_OK("Created the overall majority data for the reserve bytes");

    // wait for the block verifiers to process the votes

    if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
        if (sync_block_verifiers_minutes_and_seconds(2, 45) == XCASH_ERROR) {
            return ROUND_NEXT;
        }
    } else {
        if (sync_block_verifiers_minutes_and_seconds((BLOCK_TIME - 1), 0) == XCASH_ERROR) {
            return ROUND_SKIP;
        }
    }

    // strncmp(current_round_part_backup_node,"0",1) == 0 ? sync_block_verifiers_minutes_and_seconds(2,45) :
    // sync_block_verifiers_minutes_and_seconds((BLOCK_TIME -1),0);

    INFO_STAGE_PRINT("Part 23 - Send the overall majority data for the reserve bytes to all block verifiers");

    // send the message to all block verifiers

    replies = NULL;
    if (!xnet_send_data_multi(XNET_DELEGATES_ALL_ONLINE, (const char*)data, &replies)) {
        WARNING_PRINT("Could not send the overall majority data for the reserve bytes to all block verifiers");
        cleanup_responses(replies);
        return ROUND_NEXT;
    }
    cleanup_responses(replies);

    // if (block_verifiers_send_data_socket((const char*)data) == 0)
    // {
    //   RESTART_ROUND("Could not send the overall majority data for the reserve bytes to all block verifiers");
    // }

    INFO_PRINT_STATUS_OK("Sent the overall majority data for the reserve bytes to all block verifiers");

    INFO_STAGE_PRINT("Part 24 - Wait for all block verifiers to receive the overall majority data for the reserve bytes");

    // wait for the block verifiers to process the votes

    if (strncmp(current_round_part_backup_node, "0", 1) == 0) {
        if (sync_block_verifiers_minutes_and_seconds(2, 55) == XCASH_ERROR) {
            return ROUND_NEXT;
        }
    } else {
        if (sync_block_verifiers_minutes_and_seconds((BLOCK_TIME - 1), 10) == XCASH_ERROR) {
            return ROUND_SKIP;
        }
    }

    // strncmp(current_round_part_backup_node,"0",1) == 0 ? sync_block_verifiers_minutes_and_seconds(2,55) :
    // sync_block_verifiers_minutes_and_seconds((BLOCK_TIME -1),10);

    INFO_STAGE_PRINT("Part 25 - Check if there was an overall majority for the reserve bytes");

    // check for an overall majority
    if (current_round_part_vote_data.vote_results_valid >= BLOCK_VERIFIERS_VALID_AMOUNT) {
        INFO_PRINT_STATUS_OK("[%d / %d] block verifiers have an overall majority for the reserve bytes", current_round_part_vote_data.vote_results_valid, BLOCK_VERIFIERS_VALID_AMOUNT);
    } else {
        if (current_round_part_vote_data.vote_results_valid == 0 ||
            current_round_part_vote_data.vote_results_valid == 1) {
            // check if your delegate is a current block verifier
            for (count3 = 0; count3 < BLOCK_VERIFIERS_AMOUNT; count3++) {
                if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count3],
                            xcash_wallet_public_address, XCASH_WALLET_LENGTH) == 0) {
                    break;
                }
            }

            if (count3 != BLOCK_VERIFIERS_AMOUNT) {
                // your delegate is a current block verifier, restart the delegate as it could only verify its own
                // message and not anyone elses message
                WARNING_PRINT("Restarting, could not process any other block verifiers data");
                //! wft?
                // FIXME check memory etc
                return ROUND_SKIP;

                // exit(0);
            }
        }
        INFO_PRINT_STATUS_FAIL("[%d / %d] block verifiers have an overall majority for the reserve bytes",current_round_part_vote_data.vote_results_valid, BLOCK_VERIFIERS_VALID_AMOUNT);
        WARNING_PRINT("An invalid amount of block verifiers have an overall majority for the reserve bytes");
        return ROUND_NEXT;
    }

    // update the database and submit the block to the network
    if (block_verifiers_create_block_and_update_database() == XCASH_ERROR) {
      return ROUND_ERROR;
    }
    return ROUND_OK;

#undef RESTART_ROUND
}

/*
-----------------------------------------------------------------------------------------------------------
Name: sync_block_verifiers_minutes_and_seconds
Description: Syncs the block verifiers to a specific minute and second
Parameters:
  minutes - The minutes
  seconds - The seconds
-----------------------------------------------------------------------------------------------------------
*/

int sync_block_verifiers_minutes_and_seconds(const int MINUTES, const int SECONDS)
{
  // Variables
  // time_t current_date_and_time;
  // struct tm current_UTC_date_and_time;

  struct timeval current_time;

  gettimeofday(&current_time, NULL);

  size_t seconds_within_block = current_time.tv_sec % (BLOCK_TIME * 60);
  size_t sleep_till_time = MINUTES * 60 + SECONDS;
  if (seconds_within_block > sleep_till_time) {
      WARNING_PRINT("Sleep time exceeded current time by %ld seconds", seconds_within_block - sleep_till_time);
      return XCASH_ERROR;
  }

  DEBUG_PRINT("Sleeping for %ld seconds...", sleep_till_time-seconds_within_block);
  sleep(sleep_till_time-seconds_within_block);

  return XCASH_OK;

  // do
  // {
  //   nanosleep((const struct timespec[]){{0, 200000000L}}, NULL);
  //   time(&current_date_and_time);
  //   gmtime_r(&current_date_and_time,&current_UTC_date_and_time);
  // } while (current_UTC_date_and_time.tm_min % BLOCK_TIME != MINUTES || current_UTC_date_and_time.tm_sec != SECONDS);

  // return;
}



/*
-----------------------------------------------------------------------------------------------------------
Name: get_network_data_nodes_online_status
Description: Get all of the network data nodes online status
Return: 0 if no network data nodes are online, 1 if there is at least one network data node online
-----------------------------------------------------------------------------------------------------------
*/

int get_network_data_nodes_online_status(void) {
    response_t** replies = NULL;
    int result = XCASH_ERROR;

    INFO_STAGE_PRINT("Checking seed nodes online status");

    bool send_result =
        send_message(XNET_SEEDS_ALL, XMSG_BLOCK_VERIFIERS_TO_NETWORK_DATA_NODE_BLOCK_VERIFIERS_CURRENT_TIME, &replies);

    if (send_result) {
        int i = 0;
        while (replies[i]) {
            if (replies[i]->status == STATUS_OK) {
                network_data_nodes_list.online_status[i] = 1;
                INFO_PRINT(HOST_OK_STATUS("%s", "is online"), replies[i]->host);
                result = XCASH_OK;
            } else {
                network_data_nodes_list.online_status[i] = 0;
                INFO_PRINT(HOST_FALSE_STATUS("%s", "is offline"), replies[i]->host);
            }
            i++;
        }
    }
    // we need to cleanup always
    cleanup_responses(replies);

    return result;
}


/*
-----------------------------------------------------------------------------------------------------------
Name: block_verifiers_send_data_socket
Description: Sends the message to all of the block verifiers
Parameters:
  MESSAGE - The message that the block verifier will send to the other block verifiers
Return: 0 if an error has occured, 1 if successfull
-----------------------------------------------------------------------------------------------------------
*/

int block_verifiers_send_data_socket(const char* MESSAGE)
{
  // Constants
  const int TOTAL_BLOCK_VERIFIERS = test_settings == 0 ? BLOCK_VERIFIERS_AMOUNT : BLOCK_VERIFIERS_TOTAL_AMOUNT; 

  // Variables
  char data[BUFFER_SIZE];
  char data2[SMALL_BUFFER_SIZE];
  char data3[SMALL_BUFFER_SIZE];
  time_t current_date_and_time;
  struct tm current_UTC_date_and_time;
  int epoll_fd_copy;
  struct epoll_event events[TOTAL_BLOCK_VERIFIERS];
  struct timeval SOCKET_TIMEOUT = {SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS, 0};   
  struct block_verifiers_send_data_socket block_verifiers_send_data_socket[TOTAL_BLOCK_VERIFIERS];
  size_t total;
  size_t sent;
  long long int bytes = 1;
  int count;
  int count2;
  int number;

  // define macros
  #define BLOCK_VERIFIERS_SEND_DATA_SOCKET(message) \
  memcpy(error_message.function[error_message.total],"block_verifiers_send_data_socket",32); \
  memcpy(error_message.data[error_message.total],message,strnlen(message,BUFFER_SIZE)); \
  error_message.total++; \
  return 0;

  memset(data,0,sizeof(data));
  memset(data2,0,sizeof(data2));
  memset(data3,0,sizeof(data3));

  // create the message
  memcpy(data,MESSAGE,strnlen(MESSAGE,sizeof(data)));
  memcpy(data+strlen(data),SOCKET_END_STRING,sizeof(SOCKET_END_STRING)-1);
  total = strnlen(data,BUFFER_SIZE);
  
  // create the epoll file descriptor
  if ((epoll_fd_copy = epoll_create1(0)) == -1)
  {
    BLOCK_VERIFIERS_SEND_DATA_SOCKET("Error creating the epoll file descriptor");
  }

  // convert the port to a string
  snprintf(data2,sizeof(data2)-1,"%d",SEND_DATA_PORT);
  
  for (count = 0; count < TOTAL_BLOCK_VERIFIERS; count++)
  {    
    if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count],xcash_wallet_public_address,XCASH_WALLET_LENGTH) != 0)
    {
      // Variables
      struct addrinfo serv_addr;
      struct addrinfo* settings = NULL;

      // initialize the block_verifiers_send_data_socket struct
      memset(block_verifiers_send_data_socket[count].IP_address,0,sizeof(block_verifiers_send_data_socket[count].IP_address));
      memcpy(block_verifiers_send_data_socket[count].IP_address,current_block_verifiers_list.block_verifiers_IP_address[count],strnlen(current_block_verifiers_list.block_verifiers_IP_address[count],sizeof(block_verifiers_send_data_socket[count].IP_address)));
      block_verifiers_send_data_socket[count].settings = 0;

      // set up the addrinfo
      memset(&serv_addr, 0, sizeof(serv_addr));
      if (check_if_IP_address_or_hostname(block_verifiers_send_data_socket[count].IP_address) == 1)
      {
        /* the host is an IP address
        AI_NUMERICSERV = Specifies that getaddrinfo is provided a numerical port
        AI_NUMERICHOST = The host is already an IP address, and this will have getaddrinfo not lookup the hostname
        AF_INET = IPV4 support
        SOCK_STREAM = TCP protocol
        */
        serv_addr.ai_flags = AI_NUMERICSERV | AI_NUMERICHOST;
        serv_addr.ai_family = AF_INET;
        serv_addr.ai_socktype = SOCK_STREAM;
      }
      else
      {
        /* the host is a domain name
        AI_NUMERICSERV = Specifies that getaddrinfo is provided a numerical port
        AF_INET = IPV4 support
        SOCK_STREAM = TCP protocol
        */
        serv_addr.ai_flags = AI_NUMERICSERV;
        serv_addr.ai_family = AF_INET;
        serv_addr.ai_socktype = SOCK_STREAM;
      }
  
      // convert the hostname if used, to an IP address
      memset(data3,0,sizeof(data3));
      memcpy(data3,block_verifiers_send_data_socket[count].IP_address,strnlen(block_verifiers_send_data_socket[count].IP_address,sizeof(data3)));
      if (getaddrinfo(data3, data2, &serv_addr, &settings) != 0)
      { 
        freeaddrinfo(settings);
        continue;
      }

      /* Create the socket  
      AF_INET = IPV4 support
      SOCK_STREAM = TCP protocol
      SOCK_NONBLOCK = Non blocking socket, so it will be able to use a custom timeout
      */
      if ((block_verifiers_send_data_socket[count].socket = socket(settings->ai_family, settings->ai_socktype | SOCK_NONBLOCK, settings->ai_protocol)) == -1)
      {
        freeaddrinfo(settings);
        continue;
      }

      /* Set the socket options for sending and receiving data
      SOL_SOCKET = socket level
      SO_SNDTIMEO = allow the socket on sending data, to use the timeout settings
      */
      if (setsockopt(block_verifiers_send_data_socket[count].socket, SOL_SOCKET, SO_SNDTIMEO,&SOCKET_TIMEOUT, sizeof(struct timeval)) != 0)
      { 
        freeaddrinfo(settings);
        continue;
      } 

      /* create the epoll_event struct
      EPOLLIN = signal when the file descriptor is ready to read
      EPOLLOUT = signal when the file descriptor is ready to write
      EPOLLONESHOT = set the socket to only signal its ready once, since were using multiple threads
      */  
      events[count].events = EPOLLIN | EPOLLOUT | EPOLLONESHOT;
      events[count].data.fd = block_verifiers_send_data_socket[count].socket;

      // add the delegates socket to the epoll file descriptor
      epoll_ctl(epoll_fd_copy, EPOLL_CTL_ADD, block_verifiers_send_data_socket[count].socket, &events[count]);

      // connect to the delegate
      connect(block_verifiers_send_data_socket[count].socket,settings->ai_addr, settings->ai_addrlen);

      freeaddrinfo(settings);
    }
  }

  // wait for all of the sockets to connect. Wait for 3 seconds instead of 1 since servers time can be synced up to 3 seconds
  sleep(BLOCK_VERIFIERS_SETTINGS);

  // get the total amount of sockets that are ready
  number = epoll_wait(epoll_fd_copy, events, TOTAL_BLOCK_VERIFIERS, 0);

  for (count = 0; count < number; count++)
  {
    // check that the socket is connected
    if (events[count].events & EPOLLIN || events[count].events & EPOLLOUT)
    {
      // set the settings of the delegate to 1
      for (count2 = 0; count2 < TOTAL_BLOCK_VERIFIERS; count2++)
      {
        if (events[count].data.fd == block_verifiers_send_data_socket[count2].socket)
        {
          block_verifiers_send_data_socket[count2].settings = 1;
        }
      }
    }
  }

  // get the current time
  get_current_UTC_time(current_date_and_time,current_UTC_date_and_time);

  for (count = 0; count < TOTAL_BLOCK_VERIFIERS; count++)
  {
    if (block_verifiers_send_data_socket[count].settings == 1)
    {
      for (sent = 0; sent < total; sent += bytes == -1 ? 0 : bytes)
      {
        if ((bytes = send(block_verifiers_send_data_socket[count].socket,data+sent,total-sent,MSG_NOSIGNAL)) == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
        {           
          break;
        }
      }
    }    
  }

  // wait for all of the data to be sent to the connected sockets
  strstr(MESSAGE,"\"message_settings\": \"NETWORK_DATA_NODES_TO_NETWORK_DATA_NODES_DATABASE_SYNC_CHECK\"") != NULL ? sleep(18) : sleep(3);

  // remove all of the sockets from the epoll file descriptor and close all of the sockets
  for (count = 0; count < TOTAL_BLOCK_VERIFIERS; count++)
  {
    epoll_ctl(epoll_fd_copy, EPOLL_CTL_DEL, block_verifiers_send_data_socket[count].socket, &events[count]);
    close(block_verifiers_send_data_socket[count].socket);
  }
  return 1;
  
  #undef BLOCK_VERIFIERS_SEND_DATA_SOCKET
}


