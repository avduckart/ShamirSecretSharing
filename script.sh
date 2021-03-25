#!/bin/bash

cmake .
cmake --build .
cmake --build . --target test
cmake --build . --target package

valgrind --tool=memcheck --leak-check=yes --track-origins=yes -s build/Release/shamir_test
valgrind --tool=helgrind ./shamir_test
