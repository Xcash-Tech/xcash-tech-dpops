#!/bin/bash

# Replace these variables with the appropriate values
XCASH_MONGO_URI="mongodb://127.0.0.1:27017/XCASH_PROOF_OF_STAKE"

# Create the index
mongo "$XCASH_MONGO_URI" --eval "db.hashes2.createIndex({\"db_name\": 1})"
mongo "$XCASH_MONGO_URI" --eval "db.reserve_bytes_814.createIndex({\"block_height\": 1})"
