#!/bin/bash

# Set the script to exit if any command fails
set -e

echo "Migration script for Delegates from X-CASH to Xcash Tech"

if [[ -d "xcash-core" && -d "xcash-dpops" ]]; then
    echo "Both xcash-core and xcash-dpops directories found."
else
    echo "Run this script only from main Xcash installation dirrectory eg xcash-official"
    exit 1
fi


echo "Updating core codebase"
cd xcash-core
git remote set-url origin https://github.com/Xcash-Tech/xcash-tech-core.git
git pull
make clean
make release -j $(nproc)

echo "Updating dpops codebase"
cd ../xcash-dpops
git remote set-url origin https://github.com/Xcash-Tech/xcash-tech-dpops.git
git pull
make clean
make release -j $(nproc)


echo "Cleaning up database from old seed nodes"
mongo XCASH_PROOF_OF_STAKE --eval 'db.delegates.remove({"IP_address": {$regex: "xcash.foundation", $options: "i"}})'
