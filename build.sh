#!/bin/bash

if [ "$1" = "-c" ]
    then :
    rm -r ./build
    rm -r ./bin
    rm -r ./lib
fi

mkdir -p build
cd build
cmake ..
make
cd ..
