#!/usr/bin/env bash
set -euo pipefail

# Install GoogleTest and build static libraries for linking
if ! command -v g++ >/dev/null; then
  echo "g++ is required" >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y libgtest-dev cmake

cd /usr/src/gtest
sudo cmake .
sudo make
sudo cp lib/*.a /usr/lib/
