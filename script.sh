#!/bin/bash

cmake .
cmake --build .
cmake --build . --target test
cmake --build . --target package

valgrind --tool=memcheck --leak-check=yes --track-origins=yes -s build/Release/shamir_test
valgrind --tool=helgrind build/Release/shamir_test

rm -rf coverage
mkdir coverage
build/Release/shamir_test
gcovr --filter source/ headers/ --print-summary --html-details -o coverage/index.html
