#!/usr/bin/env bash
# MoonBit 校验流程，供 GitHub Actions 与 CNB 流水线共同调用。
# 调用方需保证环境中已安装 MoonBit 工具链（moon）。

set -euo pipefail

cd "$(dirname "$0")/.."

echo "== MoonBit version"
moon version --all

echo "== moon check"
moon fmt --check
moon check --deny-warn
moon info
git diff --exit-code
git status

echo "== moon test"
for target in wasm-gc wasm js native; do
  echo "== testing $target"
  moon test --target "$target" --deny-warn
done

echo "== moon test coverage"
moon test --deny-warn --enable-coverage
moon coverage report -f summary
moon coverage analyze

echo "== moon build"
for target in wasm-gc wasm js native; do
  echo "== building $target"
  moon build --target "$target"
  moon build --target "$target" --release
done

echo "== moon run cmd"
moon run cmd/sm2
moon run cmd/sm3
moon run cmd/sm4
