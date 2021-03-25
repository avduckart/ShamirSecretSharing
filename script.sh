#!/bin/bash

cmake .
cmake --build .
cmake --build . --target test
cmake --build . --target package

valgrind --tool=memcheck --leak-check=yes --track-origins=yes build/Release/shamir_test
