#!/bin/bash

cmake -DCMAKE_BUILD_TYPE=Debug .
cmake -DCMAKE_BUILD_TYPE=Debug --build .
cmake -DCMAKE_BUILD_TYPE=Debug --build . --target test
cmake -DCMAKE_BUILD_TYPE=Debug --build . --target package

valgrind --tool=memcheck --leak-check=yes build/Release/shamir_test
