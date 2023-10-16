#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <argp.h>
#include <signal.h>


#include "variables.h"
#include "xcash_db.h"

#include "arg_config.h"
#include "init_processing.h"
#include "round.h"
#include "xnet_helpers.h"
#include "VRF_functions.h"


const char *argp_program_version = "Xcash Tech DPoPS v. 1.3.1_2";
const char *argp_program_bug_address = "https://github.com/Xcash-Tech/xcash-tech-dpops/issues";

static char doc[] = "Usage: xcash-dpops [OPTIONS]\n"
"\n"
BRIGHT_WHITE_TEXT("General Options:\n")
"  -h, --help                              List all valid parameters.\n"
"  -k, --block-verifiers-secret-key <KEY>  Set the block verifier's secret key\n"
"\n"
BRIGHT_WHITE_TEXT("Debug Options:\n")
"  -d, --debug                             Display all server messages.\n"
// "  -e, --debug-delegates-error             Show delegates not sending messages for parts of the round.\n"
"  --log-file FILE                         Log all output without colors to FILE.\n"
"  --log-file-color FILE                   Log all output with colors to FILE.\n"
"\n"
BRIGHT_WHITE_TEXT("Network Options:\n")
"  --delegates-ip-address IP               Set delegate's IP address (Default: 0.0.0.0).\n"
"  --xcash-daemon-ip-address IP            Set daemon IP address (Default: 127.0.0.1) on port 18281.\n"
"  --xcash-wallet-ip-address IP            Set wallet RPC IP address (Default: 127.0.0.1).on port 18285\n"
"  --xcash-wallet-port PORT                Set X-Cash wallet port (Default: 18285).\n"
"  --mongodb-uri URI                       Set MongoDB URI address (Default: mongodb://127.0.0.1:27017)\n"
"\n"
BRIGHT_WHITE_TEXT("Database Options:\n")
"  --database-name NAME                    Set database name (Default: XCASH_PROOF_OF_STAKE).\n"
"  --shared-delegates-database-name NAME   Set shared delegates database name (Default: XCASH_PROOF_OF_STAKE_DELEGATES).\n"
// "  --synchronize-database-from-network-data-node  Sync database from a network data node.\n"
// "  --synchronize-database-from-specific-delegate IP  Sync database from a specific node without majority checks.\n"
"\n"
BRIGHT_WHITE_TEXT("Website Options: (deprecated)\n")
"  --delegates-website                  Run the delegate's website.\n"
"  --shared-delegates-website           Run shared delegate's website with specified fee and minimum amount.\n"
"\n"
BRIGHT_WHITE_TEXT("Delegate Options: (deprecated)\n")
"  --fee  <reward>                                  The fee reward to running delegate (0..100).\n"
"  --minimum-amount <minimum-amount>                The minimum amount of payouts to voters.\n"
"  --voter-inactivity-count [number_of_days] Voter inactivity count is optional. Number of consecutive days where a voter would have registered in the database, but is not actively participating towards the shared delegate. If this number of consecutive days is reached, the voter will be removed from the database and all funds that were left over would not sent out, since they were below the MINIMUM AMOUNT. If this parameter is not specified, the default amount is 30 consecutive days.\n"
"  --private-group <full path to configuration file> - Allows the shared delegate to use a private group. This allows for only specific voters to be paid by the shared delegate, and or the shared delegate to send payments to different public addresses than the voted for public address.\nProvide a configuration with the following format:\nname1|public_address_of_vote|public_address_that_payment_should_go_to\nname2|public_address_of_vote|public_address_that_payment_should_go_to\n\nYou can use # as comments in the file, so dont use # in any name, as comments have to be on there own separate text file line.\nYou can have up to 100 private group members for the delegate.\nThe file gets loaded at startup and every block, so dont save an incomplete config file.\n" 
"\n"
BRIGHT_WHITE_TEXT("Advanced Options:\n")
"  --total-threads THREADS                 Set total threads (Default: CPU total threads).\n"
"  --generate-key                       Generate public/private key for block verifiers.\n"
// "  --disable-synchronizing-databases-and-starting-timers  Disable DB sync and timers (For testing).\n"
// "  --registration-mode TIME             Run registration mode for network data nodes.\n"
// "  --start-time TIME                    Start current block height timer at a specific time.\n"
"\n"
"For more details on each option, refer to the documentation or use the --help option."
;



static struct argp_option options[] = {
    {"help", 'h', 0, 0, "List all valid parameters.", 0},
    {"block-verifiers-secret-key", 'k', "SECRET_KEY", 0, "Set the block verifier's secret key", 0},
    {"delegates-ip-address", OPTION_DELEGATES_IP_ADDRESS, "IP", 0, "Set delegate's IP address (Default: 0.0.0.0).", 0},
    {"xcash-daemon-ip-address", OPTION_XCASH_DAEMON_IP_ADDRESS, "IP", 0, "Set daemon IP address (Default: 127.0.0.1) on port 18281.", 0},
    {"xcash-wallet-ip-address", OPTION_XCASH_WALLET_IP_ADDRESS, "IP", 0, "Set wallet RPC IP address (Default: 127.0.0.1).on port 18285", 0},
    {"xcash-wallet-port", OPTION_XCASH_WALLET_PORT, "PORT", 0, "Set X-Cash wallet port (Default: 18285).", 0},
    {"mongodb-uri", OPTION_MONGODB_URI, "URI", 0, "Set MongoDB IP address (Default: mongodb://127.0.0.1:27017)", 0},
    {"database-name", OPTION_DATABASE_NAME, "NAME", 0, "Set database name (Default: XCASH_PROOF_OF_STAKE).", 0},
    {"shared-delegates-database-name", OPTION_SHARED_DELEGATES_DATABASE_NAME, "NAME", 0, "Set shared delegates database name (Default: XCASH_PROOF_OF_STAKE_DELEGATES).", 0},
    {"delegates-website", OPTION_DELEGATES_WEBSITE, 0, 0, "Run the delegate's website.", 0},
    {"shared-delegates-website", OPTION_SHARED_DELEGATES_WEBSITE, 0, 0, "Run shared delegate's website with specified fee and minimum amount.", 0},
    {"fee", OPTION_FEE, "FEE", 0, "The fee reward to running delegate (in percents 0..100).", 0},
    {"minimum-amount", OPTION_MINIMUM_AMOUNT, "MINIMUM_PAYOUT", 0, "The minimum amount of payouts to voters.", 0},
    {"voter-inactivity-count", OPTION_VOTER_INACTIVITY_COUNT, "NUMBER_OF_DAYS", OPTION_ARG_OPTIONAL, "Voter inactivity count. Default is 30 consecutive days.", 0},
    {"private-group", OPTION_PRIVATE_GROUP, "<full path to configuration file>", 0, "Allows the shared delegate to use a private group.", 0},
    {"generate-key", OPTION_GENERATE_KEY, 0, 0, "Generate public/private key for block verifiers.", 0},
    // {"disable-synchronizing-databases-and-starting-timers", 0, 0, 0, "Disable DB sync and timers (For testing).", 0},
    // {"registration-mode", 0, "TIME", 0, "Run registration mode for network data nodes.", 0},
    // {"start-time", 0, "TIME", 0, "Start current block height timer at a specific time.", 0},
    // {"test", 't', 0, 0, "Run a system compatibility test (Takes up to ~24h).", 0},
    // {"quick-test", 'q', 0, 0, "Run a quick system compatibility test (Takes up to ~10min).", 0},
    // {"optimization-test", 0, 0, 0, "Run an optimization test to check system performance.", 0},
    // {"test-mode", 0, "SETTING", 0, "Use test network data nodes (Setting: 1-9).", 0},
    {"debug", OPTION_DEBUG, 0, 0, "Display all server messages.", 0},
    // {"debug-delegates-error", OPTION_DEBUG_DELEGATES_ERROR, 0, 0, "Show delegates not sending messages for parts of the round.", 0},
    {"log-file", OPTION_LOG_FILE, "FILE", 0, "Log all output without colors to FILE.", 0},
    {"log-file-color", OPTION_LOG_FILE_COLOR, "FILE", 0, "Log all output with colors to FILE.", 0},
    // {"synchronize-database-from-network-data-node", OPTION_SYNCHRONIZE_DATABASE_FROM_NETWORK_DATA_NODE, 0, 0, "Sync database from a network data node.", 0},
    // {"synchronize-database-from-specific-delegate", OPTION_SYNCHRONIZE_DATABASE_FROM_SPECIFIC_DELEGATE, "IP", 0, "Sync database from a specific node without majority checks.", 0},
    {"total-threads", OPTION_TOTAL_THREADS, "THREADS", 0, "Set total threads (Default: CPU total threads).", 0},
    {"server-log-file", OPTION_SERVER_LOG_FILE, "FILE", 0, "Log server messages", 0},
    {"init-db-from-seeds", OPTION_INIT_DB_FROM_SEEDS, 0, 0, "Sync current node data from seeds. Needed only during installation process", 0},
    {"init-db-from-top", OPTION_INIT_DB_FROM_TOP, 0, 0, "Sync current node data from top block_height nodes.", 0},

    {0}
};




static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    arg_config_t *arguments = state->input;

    switch (key) {
        case 'k':
            arguments->block_verifiers_secret_key = arg;
            break;
        case OPTION_DELEGATES_IP_ADDRESS:
            arguments->delegates_ip_address = arg;
            break;
        case OPTION_XCASH_DAEMON_IP_ADDRESS:
            arguments->xcash_daemon_ip_address = arg;
            break;
        case OPTION_XCASH_WALLET_IP_ADDRESS:
            arguments->xcash_wallet_ip_address = arg;
            break;
        case OPTION_XCASH_WALLET_PORT:
            arguments->xcash_wallet_port = atoi(arg);
            break;
        case OPTION_MONGODB_URI:
            arguments->mongodb_uri = arg;
            break;
        case OPTION_DATABASE_NAME:
            arguments->database_name = arg;
            break;
        case OPTION_SHARED_DELEGATES_DATABASE_NAME:
            arguments->shared_delegates_database_name = arg;
            break;
        case OPTION_DELEGATES_WEBSITE:
            arguments->delegates_website = true;
            break;
        case OPTION_SHARED_DELEGATES_WEBSITE:
            arguments->shared_delegates_website = true;
            break;
        case OPTION_FEE:
            arguments->fee = atof(arg);
            break;
        case OPTION_MINIMUM_AMOUNT:
            arguments->minimum_amount = strtoull(arg, NULL, 10);
            break;
        case OPTION_VOTER_INACTIVITY_COUNT:
            arguments->voter_inactivity_count = atoi(arg);
            break;
        case OPTION_PRIVATE_GROUP:
            arguments->private_group = arg;
            break;
        case OPTION_GENERATE_KEY:
            arguments->generate_key = true;
            break;
        case OPTION_DEBUG:
            arguments->debug_mode = true;
            break;
        case OPTION_DEBUG_DELEGATES_ERROR:
            arguments->debug_delegates_error = true;
            break;
        case OPTION_LOG_FILE:
            arguments->log_file_name = arg;
            break;
        case OPTION_LOG_FILE_COLOR:
            arguments->log_file_name_color = arg;
            break;
        case OPTION_SYNCHRONIZE_DATABASE_FROM_NETWORK_DATA_NODE:
            arguments->sync_dbs_from_node = true;
            break;
        case OPTION_SYNCHRONIZE_DATABASE_FROM_SPECIFIC_DELEGATE:
            arguments->sync_dbs_from_delegate_ip = arg;
            break;
        case OPTION_TOTAL_THREADS:
            arguments->total_threads = atoi(arg);
            break;
        case OPTION_SERVER_LOG_FILE:
            arguments->server_log_file = arg;
            break;
        case OPTION_INIT_DB_FROM_SEEDS:
            arguments->init_db_from_seeds = true;
            break;
        case OPTION_INIT_DB_FROM_TOP:
            arguments->init_db_from_top = true;
            break;


        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, 0, doc, NULL, NULL, NULL};

void fix_pipe(int fd)
{
  if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
    return;
  }

  int f = open("/dev/null", fd == STDIN_FILENO ? O_RDONLY : O_WRONLY);
  if (f == -1) {
    FATAL_ERROR_EXIT("failed to open /dev/null for missing stdio pipe");
    // abort();
  }
  if (f != fd) {
    dup2(f, fd);
    close(f);
  }
}


void fix_std_pipes(void) {
  fix_pipe(STDIN_FILENO);
  fix_pipe(STDOUT_FILENO);
  fix_pipe(STDERR_FILENO);

}



void sigint_handler(int sig_num) {
    /* Signal handler function */
    sig_requests++;
    INFO_PRINT("Termination signal %d received [%d] times. Shutting down...", sig_num, sig_requests);
    is_shutdown_state = true;

    while(sig_requests < 3 && threads_running> 0) {
        INFO_PRINT("Shutting down. Threads still running %d...", threads_running);
        poke_dpops_port();
        sleep(1);
    }
    INFO_PRINT("Shutting down. Threads remains %d", threads_running);
    INFO_PRINT("Shutting down database engine");
    
    cleanup_data_structures();
    shutdown_database();
    fclose(server_log_fp);

    exit(0);
}


int main(int argc, char **argv) {
    arg_config_t arg_config = {0};
    
    setenv("ARGP_HELP_FMT", "rmargin=120", 1);

    if (argc == 1) {
        argp_help(&argp, stdout, ARGP_HELP_STD_HELP, argv[0]);
        return 0;
    }

    if (argp_parse(&argp, argc, argv, 0, 0, &arg_config) != 0) {
        argp_help(&argp, stdout, ARGP_HELP_STD_HELP, argv[0]);
        return 1;
    }

    if (arg_config.generate_key) {
        generate_key();
        return 0;
    }
    
    if (!arg_config.block_verifiers_secret_key) {
        ERROR_PRINT("--block-verifiers-secret-key is mandatory!");
        return 1;
    }

    // uvlib can cause assertion errors if some of STD PIPES closed
    fix_std_pipes();

    if (!initialize_database(arg_config.mongodb_uri)){
        ERROR_PRINT("Can't initialize mongo database");
        return 1;
    }

    signal(SIGINT, sigint_handler);

    if (processing(&arg_config)) {
        start_block_production();
    }

    shutdown_database();
    if (server_log_fp)
        fclose(server_log_fp);


    return 0;
}


