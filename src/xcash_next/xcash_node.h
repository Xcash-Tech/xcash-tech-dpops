#ifndef XCASH_NODE_H
#define XCASH_NODE_H
#include <stdbool.h>

bool get_node_data(void);
bool is_seed_address(const char* public_address);
const char* address_to_node_name(const char* public_address);
const char* address_to_node_host(const char* public_address);

#endif  // XCASH_NODE_H
