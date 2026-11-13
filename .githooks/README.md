# Git Hooks

## Pre-commit Hook

This pre-commit hook performs automatic checks before finalizing your commit.
It runs the same core checks as CI: `moon fmt --check`, `moon check --deny-warn`
and `moon test --deny-warn`. If any of them fail the commit is aborted.

### Usage Instructions

To use this pre-commit hook:

1. Make the hook executable if it isn't already:
   ```bash
   chmod +x .githooks/pre-commit
   ```

2. Configure Git to use the hooks in the .githooks directory:
   ```bash
   git config core.hooksPath .githooks
   ```

3. The hook will automatically run when you execute `git commit`
