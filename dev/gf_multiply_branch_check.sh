#!/bin/bash
set -euo pipefail

g++ -std=c++17 -O2 -I./include -c ./src/aes.cpp -o /tmp/aes.o
# Display branch instructions in GF_Multiply to verify absence of data-dependent branches
objdump -d /tmp/aes.o \
  | sed -n '/GF_Multiply/,/GHASH/p' \
  | grep -E '[[:space:]]j'
