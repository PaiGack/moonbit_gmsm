# paigack/gmsm

国密 SM2/SM3/SM4 算法库的 MoonBit 移植。

本项目计划将 Go 生态中成熟的国密算法库 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm)（Apache-2.0）的核心能力移植到 [MoonBit](https://www.moonbitlang.com/) 生态，提供纯 MoonBit 实现、可测试、可复用的国密基础库。

## 目标

- **SM2** 椭圆曲线公钥算法（点运算、密钥生成、`sign/verify` 数字签名）
- **SM3** 密码杂凑算法（压缩函数、消息填充、流式接口）
- **SM4** 分组密码算法（轮函数、密钥扩展、ECB/CBC 模式、PKCS7 填充）

## 状态

> 项目初始化阶段，已完成工程脚手架与 CI 搭建，算法实现尚未开始。

## 开发环境

本地开发推荐使用 CNB 提供的 `.ide/Dockerfile` 开发镜像（已预装 MoonBit 工具链与 code-server）。

## 构建与测试

使用 [MoonBit 工具链](https://www.moonbitlang.com/download)：

```bash
moon check         # 类型/语法检查
moon test          # 运行测试
moon build         # 编译
moon run cmd/main  # 运行入口程序
```

## CI

通过 GitHub Actions 在 `push` 与 `pull_request` 到 `main` 时自动执行 `moon check` / `moon test` / `moon build`，配置文件见 [.github/workflows/ci.yml](.github/workflows/ci.yml)。

## 许可证

本项目基于 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm) 移植，遵循 **Apache License 2.0**，与原项目许可证一致。详见 [LICENSE](LICENSE)。