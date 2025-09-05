#!/bin/bash
set -euo pipefail

g++ -std=c++17 -O2 -mpclmul -mssse3 -I./include -DGF_MUL_VERIFY -c ./src/aes.cpp -o /tmp/aes.o
# Fail if any branch instructions appear in GF_Multiply
if objdump -d /tmp/aes.o | sed -n '/GF_Multiply/,/GHASH/p' | grep -E '[[:space:]]j'; then
  echo "Error: branch instructions detected in GF_Multiply"
  exit 1
fi
