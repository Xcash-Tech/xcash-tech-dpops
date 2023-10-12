#ifndef XCASH_NET_H
#define XCASH_NET_H

#include <stdlib.h>
#include "xcash_message.h"
#include "uv_net.h"

typedef enum XNET_DEST{
    XNET_SEEDS_1,
    XNET_SEEDS_2,
    XNET_SEEDS_3,
    XNET_SEEDS_4,
    XNET_SEEDS_5,
    XNET_SEEDS_ALL,
    XNET_SEEDS_ALL_ONLINE,
    XNET_DELEGATES_ALL,
    XNET_DELEGATES_ALL_ONLINE,

    XNET_SINGLE
} xcash_dest_t;


bool xnet_send_data_multi(xcash_dest_t dest, const char* message, response_t ***reply);

bool send_message_param_list(xcash_dest_t dest, xcash_msg_t msg, response_t ***reply, char** pair_params);

bool send_message_param(xcash_dest_t dest, xcash_msg_t msg, response_t ***reply, ...);

bool send_message(xcash_dest_t dest, xcash_msg_t message, response_t ***reply);

bool send_direct_message_param_list(char *host, xcash_msg_t msg, response_t ***reply, char **pair_params);

bool send_direct_message_param(char* host, xcash_msg_t msg, response_t ***reply, ...);

bool send_direct_message(char* host, xcash_msg_t msg, response_t ***reply);

#endif // XCASH_NET_H
