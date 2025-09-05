# Agent Instructions

## Commit Messages

- Use Conventional Commits format: `type(scope): summary`.
- The header must be in English.
- Include a body that describes the change.

## Changes

- Keep diffs minimal and focused.
- Do not refactor or apply style changes beyond the lines you directly touch.

## Tooling
- Run `./setup-hooks.sh` after cloning to enable the clang-format pre-commit hook.
- Ensure C/C++ sources are formatted with `clang-format` before committing.
- Run `bash dev/gf_multiply_branch_check.sh` to verify constant-time GF_Multiply.
- Run `make workflow_build_test FLAGS="-Wall -Wextra -I./include -std=c++17" TEST_FLAGS="-Wall -Wextra -I./include -std=c++17"` and `./bin/test`.
