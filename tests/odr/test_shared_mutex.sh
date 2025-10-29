#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

CXX="${CXX:-c++}"
CXXFLAGS="${CXXFLAGS:-}"
INCLUDE_DIR="${ROOT}/include"
PROGRAM="${ROOT}/tests/odr/shared_mutex_program.cpp"

"${CXX}" ${CXXFLAGS} -std=c++14 -I"${INCLUDE_DIR}" "${PROGRAM}" -o "${WORKDIR}/size14"
"${CXX}" ${CXXFLAGS} -std=c++17 -I"${INCLUDE_DIR}" "${PROGRAM}" -o "${WORKDIR}/size17"

size14="$("${WORKDIR}/size14")"
size17="$("${WORKDIR}/size17")"

if [[ "${size14}" != "${size17}" ]]; then
  echo "Detected layout mismatch: sizeof(aes_cpp::AES) differs between C++14 (${size14}) and C++17 (${size17})." >&2
  exit 1
fi

echo "AES layout matches across standards."