# paigack/gmsm

国密算法库的 MoonBit 移植。

本项目把 Go 生态里成熟的国密算法库 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm)（Apache-2.0）按 GM/T 0003-2012、GM/T 0004-2012、GM/T 0002-2012 重新实现到 [MoonBit](https://www.moonbitlang.com/) 生态。

## 主要功能

### SM2

- `GenerateKey` 生成密钥对，`PublicKey` / `PrivateKey` 推导公钥、点是否在曲线；
- `Sm2Sign` / `Sm2Verify` 数字签名（含 Z 值预处理 entl ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ x ‖ y 与 SM3 摘要）；
- `Encrypt` / `Decrypt` 加解密，支持 C1C3C2 与 C1C2C3 密文排布，对应 `CipherMarshal` / `CipherUnmarshal`；
- `KeyExchangeA` / `KeyExchangeB` 密钥协商，`Compress` / `Decompress` 公钥压缩 / 解压；
- ASN.1 签名格式 `SignDigitToSignData` / `SignDataToSignDigit`。

### SM3

- `Sm3Sum` / `Sm3SumMulti` 一次性摘要；
- 流式 `SM3`（`new / write / sum / reset / size`），输出 32 字节，对齐 Go `hash.Hash`。

### SM4

- `NewCipher` 块加密，对齐 Go `cipher.Block`；
- `Sm4Ecb` / `Sm4Cbc` / `Sm4Cfb` / `Sm4Ofb` 各模式封装，附带 PKCS7 填充与 `SetIV`；
- `Sm4Gcm` 对应 `Sm4GCM` / `GCMEncrypt` / `GCMDecrypt`。

## 当前实现状态

SM2 / SM3 / SM4 均已完成实现，并在 `cmd/` 下提供可运行的命令行 demo：

- `moon run cmd/sm2` —— 密钥生成、签名/验签、DER 签名、加密/解密（C1C2C3 与 ASN.1）、
  公钥压缩/解压、密钥协商；
- `moon run cmd/sm3` —— 一次性摘要与流式摘要，并对照 GM/T 0004-2012 标准测试向量校验；
- `moon run cmd/sm4` —— 单块加解密（对照 GM/T 0002-2012 附录 A 测试向量）、ECB/CBC 模式
  及 PKCS7 填充的往返验证。


## 构建与测试

使用 [MoonBit 工具链](https://www.moonbitlang.com/download)：

```bash
moon check         # 类型 / 语法检查
moon test          # 运行测试
moon build         # 编译
moon run cmd/sm2  # 运行 sm2 example 入口程序
moon run cmd/sm3  # 运行 sm3 example 入口程序
moon run cmd/sm4  # 运行 sm4 example 入口程序
```

## 许可证

本项目基于 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm) 移植，遵循 **Apache License 2.0**，与原项目许可证一致。详见 [LICENSE](LICENSE)。