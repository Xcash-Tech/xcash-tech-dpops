#!/bin/bash

echo "Cleaning up delegates database"
mongo XCASH_PROOF_OF_STAKE --eval 'db.delegates.drop()'
mongoimport --db XCASH_PROOF_OF_STAKE  --collection delegates --file update.json --upsert
