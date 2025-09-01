#!/usr/bin/env bash
set -euo pipefail
# Enable repo-local hooks once per clone
if [ "$(git config --local --get core.hooksPath || true)" != ".githooks" ]; then
  git config --local core.hooksPath .githooks
fi
# Make Unix hook executable (no-op on Windows)
if [ -f ".githooks/pre-commit" ]; then
  chmod +x .githooks/pre-commit || true
fi
