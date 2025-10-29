#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

CXX="${CXX:-c++}"
CXXFLAGS="${CXXFLAGS:-}"
INCLUDE_DIR="${ROOT}/include"
PROGRAM="${ROOT}/tests/odr/debug_api.cpp"

if ! "${CXX}" ${CXXFLAGS} -std=c++17 -DAESCPP_DEBUG -I"${INCLUDE_DIR}" "${PROGRAM}" -c -o "${WORKDIR}/with_debug.o"; then
  echo "Compilation with AESCPP_DEBUG enabled failed unexpectedly." >&2
  exit 1
fi

if "${CXX}" ${CXXFLAGS} -std=c++17 -I"${INCLUDE_DIR}" "${PROGRAM}" -c -o "${WORKDIR}/without_debug.o"; then
  echo "No API divergence detected: build succeeds with and without AESCPP_DEBUG." >&2
  exit 0
fi

echo "Detected API mismatch: AESCPP_DEBUG controls public surface." >&2
exit 1