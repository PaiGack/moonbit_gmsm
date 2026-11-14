#!/usr/bin/env bash
# 把当前模块发布到 mooncakes.io。
#
# 用法：
#   export MOONBIT_USERNAME=<mooncakes.io 用户名>
#   export MOONBIT_PASSWORD=<mooncakes.io 密码>
#   ./scripts/publish_to_mooncakes.sh
#
# moon login 是交互式 TUI，密码直接从 /dev/tty 读取，普通管道输入会报
# "IO error: not a terminal"。因此这里用 util-linux 的 script(1) 分配伪终端，
# 再依次选择默认的 Password 登录方式、输入用户名和密码。密码不会被回显，
# 也不会写入 typescript 文件（输出定向到 /dev/null），只从环境变量读取。

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${MOONBIT_USERNAME:-}" ]]; then
  echo "错误：未设置环境变量 MOONBIT_USERNAME" >&2
  echo "请先执行: export MOONBIT_USERNAME=<mooncakes.io 用户名>" >&2
  exit 1
fi

if [[ -z "${MOONBIT_PASSWORD:-}" ]]; then
  echo "错误：未设置环境变量 MOONBIT_PASSWORD" >&2
  echo "请先执行: export MOONBIT_PASSWORD=<mooncakes.io 密码>" >&2
  exit 1
fi

if ! command -v moon >/dev/null 2>&1; then
  echo "错误：未找到 moon 命令，请先安装 MoonBit 工具链" >&2
  exit 1
fi

if ! command -v script >/dev/null 2>&1; then
  echo "错误：未找到 script 命令（util-linux），无法为非交互式登录分配伪终端" >&2
  exit 1
fi

echo "== moon login (${MOONBIT_USERNAME})"
# 分步写入：moon login 每一步都会切换终端模式并清空输入缓冲，
# 一次性把全部内容写进管道会导致密码丢失或提前被回显。
# 用进程替换提供输入，使 script 的退出码不被输入端的 SIGPIPE 干扰。
feed_credentials() {
  printf '\r'                        # 选择默认的 "Password" 登录方式
  sleep 1
  printf '%s\r' "$MOONBIT_USERNAME" # Username:
  sleep 1
  printf '%s\r' "$MOONBIT_PASSWORD" # Password:
  sleep 1                           # 避免写完密码就关闭 stdin
}
script -q -e -c "moon login" /dev/null < <(feed_credentials)

echo "== moon publish"
moon publish

echo "== 发布完成"
