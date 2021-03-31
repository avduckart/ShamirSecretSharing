#!/bin/bash

cmake .
cmake --build .

valgrind --tool=memcheck --leak-check=yes --track-origins=yes -s build/Release/shamir_test
valgrind --tool=helgrind build/Release/shamir_test
