#!/bin/bash

cmake .
cmake --build .
cmake --build . --target test
cmake --build . --target package

valgrind --tool=memcheck build/Release/shamir_test
