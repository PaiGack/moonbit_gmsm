# paigack/gmsm

国密算法库的 MoonBit 移植。

本项目把 Go 生态里成熟的国密算法库 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm)（Apache-2.0）按 GM/T 0003-2012、GM/T 0004-2012、GM/T 0002-2012 重新实现到 [MoonBit](https://www.moonbitlang.com/) 生态，提供纯 MoonBit 实现的 SM2 / SM3 / SM4 算法。

## 现状

- `sm3/`：已实现 `sm3_sum`、`sm3_sum_multi` 与流式 `SM3`（`new / write / sum`），并按 GB/T 32905 标准向量通过 `moon test`。
- `sm2/`：已建立 P-256 推荐曲线参数与函数签名（`sm2_p256`、`generate_key`、`derive_public_key`、`is_on_curve`、`sm2_sign`、`sm2_verify`、`sm2_encrypt`、`sm2_decrypt`、`CipherMode`）；大数运算与 Z 值预处理已就位，`derive_public_key` / `sm2_verify` / `sm2_sign` 仍是占位实现，等待点运算完成后跑 GB/T 32918 向量。
- `sm4/`：尚未建立，列在后续路线。
- `gmsm` 顶层包负责把 `sm2` / `sm3` 的类型与函数聚合成 `paigack/gmsm` 单一入口。

## 构建与测试

使用 [MoonBit 工具链](https://www.moonbitlang.com/download)：

```bash
moon check         # 类型 / 语法检查
moon test          # 运行测试
moon build         # 编译
moon run cmd/main  # 运行入口程序
```

修改包内可见 API 后执行 `moon info && moon fmt` 更新 `.mbti` 接口文件与格式。

## CI

通过 GitHub Actions 在 `push` 与 `pull_request` 到 `main` 时自动执行 `moon check` / `moon test` / `moon build`，配置见 [.github/workflows/ci.yml](.github/workflows/ci.yml)。

## 许可证

本项目基于 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm) 移植，遵循 **Apache License 2.0**，与原项目许可证一致。详见 [LICENSE](LICENSE)。