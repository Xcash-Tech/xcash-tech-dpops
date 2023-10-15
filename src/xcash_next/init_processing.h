#ifndef INIT_PROCESSING_H
#define INIT_PROCESSING_H

#include <stdbool.h>
#include <arg_config.h>
#include <sys/sysinfo.h>

#include "xcash_db_sync.h"
#include "xcash_db_helpers.h"

#include "arg_config.h"
#include "variables.h"

#include "define_macro_functions.h"

#include "shared_delegate_website_thread_server_functions.h"
#include "server_functions.h"
#include "block_verifiers_thread_server_functions.h"
#include "block_verifiers_functions.h"
#include "log.h"
#include "xcash_db_sync.h"
#include "network_daemon_functions.h"
#include "xcash_node.h"


extern const char* argp_program_version;
bool get_node_data(void);
bool init_data_by_config(const arg_config_t* config);
bool processing(const arg_config_t* arg_config);

void cleanup_data_structures(void);


#endif // INIT_PROCESSING_H
