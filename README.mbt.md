# PaiGack/gmsm

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

## 快速上手

下面的示例都是可执行的文档测试，`moon test` 会直接运行它们。

### SM3 摘要

```mbt check
///|
test "sm3 digest" {
  // 一次性摘要
  let digest = @sm3.sm3_sum(b"abc")
  assert_eq(
    @hexutil.bytes_to_hex(digest),
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
  // 多段拼接摘要，等价于把各段连接后再计算
  assert_eq(
    @hexutil.bytes_to_hex(@sm3.sm3_sum_multi([b"a", b"b", b"c"])),
    @hexutil.bytes_to_hex(digest),
  )
  // 流式接口，对齐 Go 的 hash.Hash（write 返回新的上下文，链式调用）
  let h = @sm3.new().write(b"a").write(b"bc")
  assert_eq(h.size(), 32)
  assert_eq(h.block_size(), 64)
  assert_eq(@hexutil.bytes_to_hex(h.sum()), @hexutil.bytes_to_hex(digest))
  // reset 之后可以复用
  assert_eq(
    @hexutil.bytes_to_hex(h.reset().write(b"abc").sum()),
    @hexutil.bytes_to_hex(digest),
  )
}
```

### SM4 分组加密

```mbt check
///|
test "sm4 block and modes" {
  let key = @hexutil.hex_to_bytes("0123456789abcdeffedcba9876543210")
  // GM/T 0002-2012 附录 A 标准向量
  let block = @sm4.new_cipher(key)
  assert_eq(block.block_size(), 16)
  let ct = block.encrypt(key)
  assert_eq(@hexutil.bytes_to_hex(ct), "681edf34d206965e86b3e94f536e4246")
  assert_eq(
    @hexutil.bytes_to_hex(block.decrypt(ct)),
    @hexutil.bytes_to_hex(key),
  )

  // ECB / CBC 模式 + PKCS7 填充
  let msg = b"hello sm4, moonbit!"
  let iv = @hexutil.hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let padded = @sm4.pkcs7_pad(msg, 16)
  let ecb = @sm4.sm4_encrypt_ecb(key, padded)
  assert_true(
    @hexutil.bytes_eq(@sm4.pkcs7_unpad(@sm4.sm4_decrypt_ecb(key, ecb)), msg),
  )
  let cbc = @sm4.sm4_encrypt_cbc(key, iv, padded)
  assert_true(
    @hexutil.bytes_eq(@sm4.pkcs7_unpad(@sm4.sm4_decrypt_cbc(key, iv, cbc)), msg),
  )
  // CFB / OFB（128 位反馈，同样按整块处理）
  let cfb = @sm4.sm4_encrypt_cfb(key, iv, padded)
  assert_true(
    @hexutil.bytes_eq(@sm4.pkcs7_unpad(@sm4.sm4_decrypt_cfb(key, iv, cfb)), msg),
  )
  let ofb = @sm4.sm4_encrypt_ofb(key, iv, padded)
  assert_true(
    @hexutil.bytes_eq(@sm4.pkcs7_unpad(@sm4.sm4_decrypt_ofb(key, iv, ofb)), msg),
  )
  // GCM 认证加密
  let nonce = @hexutil.hex_to_bytes("000102030405060708090a0b")
  let aad = b"header"
  let (gcm_ct, tag) = @sm4.sm4_gcm_encrypt(key, nonce, msg, aad)
  let (plain, tag2) = @sm4.sm4_gcm_decrypt(key, nonce, gcm_ct, aad)
  assert_true(@hexutil.bytes_eq(plain, msg) && @hexutil.bytes_eq(tag, tag2))
}
```

### SM2 签名 / 加密

```mbt check
///|
test "sm2 sign and encrypt" {
  let sk = @sm2.generate_key(None)
  let pub_key = @sm2.derive_public_key(sk)
  let uid = @sm2.default_uid()
  let msg = b"hello sm2"

  // 裸 (r, s) 签名与 ASN.1 DER 签名
  let (r, s) = @sm2.sm2_sign(sk, msg, uid, None)
  assert_true(@sm2.sm2_verify(pub_key, msg, uid, r, s))
  let der = @sm2.sign_digit_to_sign_data(r, s)
  let (r2, s2) = @sm2.sign_data_to_sign_digit(der)
  assert_true(@hexutil.bytes_eq(r, r2) && @hexutil.bytes_eq(s, s2))
  assert_true(
    @sm2.sm2_verify_der(
      pub_key,
      msg,
      uid,
      @sm2.sm2_sign_der(sk, msg, uid, None),
    ),
  )

  // C1C3C2 / C1C2C3 两种密文排布与 ASN.1 密文
  let ct = @sm2.sm2_encrypt(pub_key, msg, None, @sm2.cipher_mode_c1c3c2())
  assert_true(
    @hexutil.bytes_eq(@sm2.sm2_decrypt(sk, ct, @sm2.cipher_mode_c1c3c2()), msg),
  )
  assert_true(
    @hexutil.bytes_eq(
      @sm2.sm2_decrypt_asn1(sk, @sm2.sm2_encrypt_asn1(pub_key, msg, None)),
      msg,
    ),
  )

  // 公钥压缩 / 解压
  let compressed = @sm2.compress_point(pub_key)
  assert_eq(compressed.length(), 33)
  assert_true(@sm2.is_on_curve(@sm2.decompress_point(compressed)))
}
```

### SM2 密钥协商

```mbt check
///|
test "sm2 key exchange" {
  let (priv_a, rpriv_a) = (@sm2.generate_key(None), @sm2.generate_key(None))
  let (priv_b, rpriv_b) = (@sm2.generate_key(None), @sm2.generate_key(None))
  let pub_a = @sm2.derive_public_key(priv_a)
  let pub_b = @sm2.derive_public_key(priv_b)
  let rpub_a = @sm2.derive_public_key(rpriv_a)
  let rpub_b = @sm2.derive_public_key(rpriv_b)
  let ida = b"1234567812345678"
  let idb = b"1234567812345678"
  let (ka, s1a, s2a) = @sm2.key_exchange_a(
    16, ida, idb, priv_a, pub_b, rpriv_a, rpub_b,
  )
  let (kb, s1b, s2b) = @sm2.key_exchange_b(
    16, ida, idb, priv_b, pub_a, rpriv_b, rpub_a,
  )
  assert_true(@hexutil.bytes_eq(ka, kb)) // 协商出同一把 16 字节会话密钥
  assert_true(@hexutil.bytes_eq(s1a, s1b) && @hexutil.bytes_eq(s2a, s2b)) // 密钥确认值一致
}
```

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