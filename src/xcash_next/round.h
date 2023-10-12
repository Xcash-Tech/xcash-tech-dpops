#ifndef ROUND_H
#define ROUND_H

#include <time.h>
#include <openssl/sha.h>

#include "define_macros.h"
#include "define_macro_functions.h"
#include "variables.h"
#include "network_daemon_functions.h"
#include "block_verifiers_functions.h"
#include "block_verifiers_thread_server_functions.h"

#include "block_verifiers_update_functions.h"
#include "xcash_db_sync.h"
#include "xcash_node.h"
#include "cached_hashes.h"

typedef struct {
    char* public_address;
    char* IP_address;
} producer_ref_t;

extern producer_ref_t producer_refs[];

typedef struct {
    char public_address[XCASH_WALLET_LENGTH+1];
    char IP_address[BLOCK_VERIFIERS_IP_ADDRESS_TOTAL_LENGTH+1];
    bool is_online;
} producer_node_t;

typedef enum {
    ROUND_ERROR, // some system fault occurred. mostly communication errors or other non-fatal error. In that case better wait till next round
    ROUND_OK, //all the procedures finished successfully
    ROUND_SKIP, // wait till next round
    ROUND_RETRY,
    ROUND_NEXT,
} xcash_round_result_t;


void select_block_producers(size_t round_number);

void select_block_producers2(size_t round_number);

void show_block_producer(size_t round_number);

xcash_round_result_t process_round(size_t round_number);

void start_block_production(void);


#endif // ROUND_H
