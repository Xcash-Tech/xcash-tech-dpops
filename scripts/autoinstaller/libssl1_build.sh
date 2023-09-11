#!/bin/bash
set -e
#if ldconfig -p | grep -q "libssl.so.1.1"; then
#    echo "libssl.so.1.1 is available on the system. You don't need to install it again"
#else
    echo Installing Libssl1.1

    wget https://www.openssl.org/source/openssl-1.1.1.tar.gz &>/dev/null
    tar xvf openssl-1.1.1.tar.gz &>/dev/null
    rm openssl-1.1.1.tar.gz 
    cd openssl-1.1.1/
    ./config no-idea
    make -j $(nproc) &>/dev/null
    sudo make install &>/dev/null
    cd ..
    rm -rf ./openssl-1.1.1
    echo Libssl1.1 is installed
#fi

