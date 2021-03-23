#!/bin/bash^M
^M
cmake .^M
cmake --build .^M
cmake --build . --target test^M
cmake --build . --target package^M
