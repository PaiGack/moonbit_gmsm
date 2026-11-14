#!/usr/bin/env bash
# 把当前分支同步推送到 GitHub 仓库 PaiGack/moonbit_gmsm。
# 仓库 HTTPS 地址：https://github.com/PaiGack/moonbit_gmsm.git
# 仓库 SSH  地址：git@github.com:PaiGack/moonbit_gmsm.git（本脚本使用 HTTPS + token）
# origin 仍指向 CNB，脚本不会修改任何 remote 配置。
#
# 用法：
#   export GITHUB_TOKEN=<具备目标仓库 Contents 写权限的 token>
#   ./scripts/sync_to_github.sh             # 普通推送（仅允许 fast-forward）
#   ./scripts/sync_to_github.sh --force    # 强制推送，使 GitHub 分支与本地一致
#
# 注意：GITHUB_TOKEN 只通过 Authorization 请求头传递，不会写入 remote URL、
# .git/config 或命令行输出。

set -euo pipefail

cd "$(dirname "$0")/.."

GITHUB_REPO="PaiGack/moonbit_gmsm"
GITHUB_URL="https://github.com/${GITHUB_REPO}.git"

usage() {
  echo "用法: GITHUB_TOKEN=<token> $0 [-f|--force]"
}

force=false
case "${1:-}" in
  "") ;;
  -f | --force) force=true ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "错误：未知参数 $1" >&2
    usage >&2
    exit 2
    ;;
esac
if [[ $# -gt 1 ]]; then
  echo "错误：最多只接受一个参数" >&2
  usage >&2
  exit 2
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "错误：未设置环境变量 GITHUB_TOKEN" >&2
  echo "请先执行: export GITHUB_TOKEN=<token>" >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "错误：当前目录不是 Git 仓库" >&2
  exit 1
fi

if ! branch="$(git symbolic-ref --quiet --short HEAD)"; then
  echo "错误：当前处于 detached HEAD，无法确定要推送的分支" >&2
  exit 1
fi

# basic 认证的用户名固定为 x-access-token，密码为 PAT。
auth="$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')"
export GIT_TERMINAL_PROMPT=0

push_to_github() {
  git \
    -c credential.helper= \
    -c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${auth}" \
    push "$@" "$GITHUB_URL" "HEAD:refs/heads/${branch}"
}

if [[ "$force" == true ]]; then
  echo "== 同步 ${branch} -> ${GITHUB_REPO}:${branch} (--force)"
  push_to_github --force
else
  echo "== 同步 ${branch} -> ${GITHUB_REPO}:${branch}"
  push_to_github
fi
echo "== 同步完成"
