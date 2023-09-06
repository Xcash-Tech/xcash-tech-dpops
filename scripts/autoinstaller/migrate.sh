#!/bin/bash

echo "Migration script fro delegates from X-CASH to Xcash Tech"
echo "run this script from main Xcash installation dirrectory eg xcash-official"


#update core codebase
cd xcash-core
git remote set-url origin https://github.com/Xcash-Tech/xcash-tech-core.git
git pull
make clean
make release - j $(nproc)

#update dpops codebase
cd ../xcash-dpops
git remote set-url origin https://github.com/Xcash-Tech/xcash-tech-dpops.git
git pull
make clean
make release - j $(nproc)

