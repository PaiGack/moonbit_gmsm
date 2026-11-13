# PaiGack/gmsm

国密算法库的 MoonBit 移植。

本项目把 Go 生态里的国密算法库 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm)（Apache-2.0）按 GM/T 0003-2012、GM/T 0004-2012、GM/T 0002-2012 重新实现到 [MoonBit](https://www.moonbitlang.com/) 生态。

## 主要功能

### SM2

- `GenerateKey` 生成密钥对，`PublicKey` / `PrivateKey` 推导公钥、点是否在曲线；
- `Sm2Sign` / `Sm2Verify` 数字签名（含 Z 值预处理 entl ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ x ‖ y 与 SM3 摘要）；
- `Encrypt` / `Decrypt` 加解密，支持 C1C3C2 与 C1C2C3 密文排布，对应 `CipherMarshal` / `CipherUnmarshal`；
- `KeyExchangeA` / `KeyExchangeB` 密钥协商，`Compress` / `Decompress` 公钥压缩 / 解压；
- ASN.1 签名格式 `SignDigitToSignData` / `SignDataToSignDigit`；
- `PublicKey::za`（Z 值）、`PublicKey::sm3_digest`（e = SM3(ZA ‖ M)）与
  `sm2_verify_digest`（对已有摘要验签，对应 Go 的 `ZA` / `Sm3Digest` / `Verify`）；
- `SM2PrivateKey::wipe()` 显式清零私钥标量。

**错误模型**：除 `compress_point` / `derive_public_key` 等纯计算外，所有
对外入口都用 `raise Sm2Error` 报告失败，**不会 abort / panic**。特别地：

- `sm2_decrypt` 只抛 `InvalidCipher`，不再区分「点不在曲线上」「KDF 全零」
  「C3 不匹配」，避免错误码本身成为解密 oracle；
- `sm2_decrypt` 的 C3 比较走 `@byteutil.ct_eq`，是常量时间；
- `key_exchange_a` / `key_exchange_b` 也返回 `raise Sm2Error`
  （`KdfZeroKey` / `NotOnCurve` / `InvalidParameter`），与其余 API 一致；
- `uid` 超过 8191 字节时统一抛 `InvalidParameter`，不再 abort。

### SM3

- `Sm3Sum` / `Sm3SumMulti` 一次性摘要；
- 流式 `SM3`（`new / write / sum / reset / size`），输出 32 字节，对齐 Go `hash.Hash`。

### SM4

- `new_cipher` 块加密，对齐 Go `cipher.Block`；
- `sm4_ecb` / `sm4_cbc` / `sm4_cfb` / `sm4_ofb` 各模式封装，附带 PKCS7 填充；
- `sm4_gcm_encrypt` / `sm4_gcm_decrypt` 标准 GCM 认证加密（NIST SP 800-38D，
  与 OpenSSL / BoringSSL / Go `crypto/cipher` 互通）；
- `sm4_gcm_encrypt_legacy` / `sm4_gcm_decrypt_legacy` 复刻 tjfoc/gmsm 的**非标准**
  GCM 输出（GHASH 长度块用字节长度、计数器进位被吞），只用于和既有 gmsm 部署互通；
- `read_key_from_pem` / `write_key_to_pem` 密钥 PEM 读写，对应 Go 的
  `ReadKeyFromPem` / `WriteKeyToPem`。**默认**用安全格式
  （PBKDF2-HMAC-SM3 → SM4-CBC → HMAC-SM3，块类型 `SM4 ENCRYPTED KEY`）；
  需要写 Go 旧版 `x509.EncryptPEMBlock`（AES-256-CBC、无盐无迭代）时显式调用
  `write_key_to_pem_legacy`，读取端两种格式都能识别。

> ⚠️ **GCM 兼容性**：默认入口 `sm4_gcm_encrypt` / `sm4_gcm_decrypt` 是**标准 GCM**；
> 与 gmsm 通信必须两端一致地改用 `_legacy` 变体。两组入口的密文 / tag **互不相同**，
> 混用表现为「加密成功但对方验签失败」。

### byteutil

- `base64_encode` / `base64_decode`（解码接受省略 padding 的输入，与 Go
  `base64.StdEncoding` 的读取端一致）；
- `pem_encode` / `pem_encode_simple` / `pem_decode` / `pem_decode_all`
  （header 段必须以空行结束，否则报错，不会把带冒号的正文行静默当成 header）；
- `hex_to_bytes`（非法字符 / 奇数长度抛 `ByteUtilError::InvalidHex`，
  不再 abort）、`hex_to_bytes_unchecked`（字面量专用，非法输入 abort）、
  `bytes_to_hex`。

**DER 严格性**：`normalize_32` 与各 `*_der` / `*_asn1` 入口要求**最小编码**——
`INTEGER 00 00 01` 这类冗余前导零被拒绝；`SEQUENCE` 之后追加任意字节同样被拒绝
（尾部必须耗尽）。同一个 r/s 或同一份密文只有唯一合法的字节表示。

## 快速上手

项目在 `cmd/` 下提供了三组命令行示例：

- `moon run cmd/sm2` —— 密钥生成、签名/验签、DER 签名、加密/解密（C1C2C3 与 ASN.1）、
  公钥压缩/解压、密钥协商；
- `moon run cmd/sm3` —— 一次性摘要与流式摘要，并对照 GM/T 0004-2012 标准测试向量校验；
- `moon run cmd/sm4` —— 单块加解密（对照 GM/T 0002-2012 附录 A 测试向量）、ECB/CBC 模式
  及 PKCS7 填充的往返验证。

以下示例为文档测试，可通过 `moon test` 运行：

### SM3 摘要

```mbt check
///|
test "sm3 digest" {
  // 一次性摘要
  let digest = @sm3.sm3_sum(b"abc")
  assert_eq(
    @byteutil.bytes_to_hex(digest),
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
  // 多段拼接摘要，等价于把各段连接后再计算
  assert_eq(
    @byteutil.bytes_to_hex(@sm3.sm3_sum_multi([b"a", b"b", b"c"])),
    @byteutil.bytes_to_hex(digest),
  )
  // 流式接口，对齐 Go 的 hash.Hash（write 返回新的上下文，链式调用）
  let h = @sm3.new().write(b"a").write(b"bc")
  assert_eq(h.size(), 32)
  assert_eq(h.block_size(), 64)
  assert_eq(@byteutil.bytes_to_hex(h.sum()), @byteutil.bytes_to_hex(digest))
  // reset 之后可以复用
  assert_eq(
    @byteutil.bytes_to_hex(h.reset().write(b"abc").sum()),
    @byteutil.bytes_to_hex(digest),
  )
}
```

### SM4 分组加密

```mbt check
///|
test "sm4 block and modes" {
  let key = @byteutil.hex_to_bytes("0123456789abcdeffedcba9876543210")
  // GM/T 0002-2012 附录 A 标准向量
  let block = @sm4.new_cipher(key)
  assert_eq(block.block_size(), 16)
  let ct = block.encrypt(key)
  assert_eq(@byteutil.bytes_to_hex(ct), "681edf34d206965e86b3e94f536e4246")
  assert_eq(
    @byteutil.bytes_to_hex(block.decrypt(ct)),
    @byteutil.bytes_to_hex(key),
  )

  // ECB / CBC 模式 + PKCS7 填充
  let msg = b"hello sm4, moonbit!"
  let iv = @byteutil.hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let padded = @byteutil.pkcs7_pad(msg, 16)
  let ecb = @sm4.sm4_encrypt_ecb(key, padded)
  let ecb_plain = @byteutil.pkcs7_unpad(@sm4.sm4_decrypt_ecb(key, ecb))
  assert_true(@byteutil.bytes_eq(ecb_plain, msg))
  let cbc = @sm4.sm4_encrypt_cbc(key, iv, padded)
  let cbc_plain = @byteutil.pkcs7_unpad(@sm4.sm4_decrypt_cbc(key, iv, cbc))
  assert_true(@byteutil.bytes_eq(cbc_plain, msg))
  // CFB / OFB（128 位反馈，同样按整块处理）
  let cfb = @sm4.sm4_encrypt_cfb(key, iv, padded)
  let cfb_plain = @byteutil.pkcs7_unpad(@sm4.sm4_decrypt_cfb(key, iv, cfb))
  assert_true(@byteutil.bytes_eq(cfb_plain, msg))
  let ofb = @sm4.sm4_encrypt_ofb(key, iv, padded)
  let ofb_plain = @byteutil.pkcs7_unpad(@sm4.sm4_decrypt_ofb(key, iv, ofb))
  assert_true(@byteutil.bytes_eq(ofb_plain, msg))
  // GCM 认证加密
  let nonce = @byteutil.hex_to_bytes("000102030405060708090a0b")
  let aad = b"header"
  // 标准 GCM（NIST SP 800-38D），与 OpenSSL / Go crypto/cipher 互通；
  // 与 gmsm 互通需改用 sm4_gcm_encrypt_legacy / sm4_gcm_decrypt_legacy。
  let (gcm_ct, tag) = @sm4.sm4_gcm_encrypt(key, nonce, msg, aad)
  // 解密校验：tag 不符会抛 SM4Error::InvalidTag，不返回明文
  let plain = @sm4.sm4_gcm_decrypt(key, nonce, gcm_ct, aad, tag)
  assert_true(@byteutil.bytes_eq(plain, msg))
  // 与 gmsm 的非标准变体结果不同（差异体现在 tag 上），两者不可混用
  let (_, legacy_tag) = @sm4.sm4_gcm_encrypt_legacy(key, nonce, msg, aad)
  assert_false(@byteutil.bytes_eq(tag, legacy_tag))
}
```

### SM2 签名 / 加密

```mbt check
///|
test "sm2 sign and encrypt" {
  let sk = @sm2.generate_key(@sm2.os_rand())
  let pub_key = @sm2.derive_public_key(sk)
  let uid = @sm2.default_uid()
  let msg = b"hello sm2"

  // 裸 (r, s) 签名与 ASN.1 DER 签名
  let (r, s) = @sm2.sm2_sign(sk, msg, uid, @sm2.os_rand())
  assert_true(@sm2.sm2_verify(pub_key, msg, uid, r, s))
  let der = @sm2.sign_digit_to_sign_data(r, s)
  let (r2, s2) = @sm2.sign_data_to_sign_digit(der)
  assert_true(@byteutil.bytes_eq(r, r2) && @byteutil.bytes_eq(s, s2))
  assert_true(
    @sm2.sm2_verify_der(
      pub_key,
      msg,
      uid,
      @sm2.sm2_sign_der(sk, msg, uid, @sm2.os_rand()),
    ),
  )

  // C1C3C2 / C1C2C3 两种密文排布与 ASN.1 密文
  let ct = @sm2.sm2_encrypt(pub_key, msg, @sm2.os_rand(), @sm2.C1C3C2)
  assert_true(@byteutil.bytes_eq(@sm2.sm2_decrypt(sk, ct, @sm2.C1C3C2), msg))
  assert_true(
    @byteutil.bytes_eq(
      @sm2.sm2_decrypt_asn1(
        sk,
        @sm2.sm2_encrypt_asn1(pub_key, msg, @sm2.os_rand()),
      ),
      msg,
    ),
  )

  // 公钥压缩 / 解压
  let compressed = @sm2.compress_point(pub_key)
  assert_eq(compressed.length(), 33)
  assert_true(@sm2.is_on_curve(@sm2.decompress_point(compressed)))
}
```

### SM2 Z 值与摘要验签

```mbt check
///|
test "sm2 za and digest verify" {
  let sk = @sm2.generate_key(@sm2.os_rand())
  let pub_key = @sm2.derive_public_key(sk)
  let uid = @sm2.default_uid()
  let msg = b"hello sm2 digest"

  // ZA 与 e = SM3(ZA ‖ M) 现在可以从外部取得
  let za = pub_key.za(uid)
  assert_eq(za.length(), 32)
  let digest = pub_key.sm3_digest(msg, uid) // uid 为空时等价于 default_uid()
  assert_true(@byteutil.bytes_eq(digest, pub_key.sm3_digest(msg, b"")))

  // 对「已算好的摘要」验签（对应 Go 的 sm2.Verify）
  let (r, s) = @sm2.sm2_sign(sk, msg, uid, @sm2.os_rand())
  assert_true(@sm2.sm2_verify_digest(pub_key, digest, r, s))
}
```

### SM4 密钥 PEM

```mbt check
///|
test "sm4 key pem" {
  let key : @sm4.SM4Key = b"0123456789abcdef"

  // 不加密
  let pem = @sm4.write_key_to_pem(key, b"", None)
  assert_true(@byteutil.bytes_eq(@sm4.read_key_from_pem(pem, b""), key))

  // 口令加密（默认）：块类型 SM4 ENCRYPTED KEY，
  // 内容为 PBKDF2-HMAC-SM3 派生密钥 + SM4-CBC + HMAC-SM3 认证
  let enc = @sm4.write_key_to_pem(key, b"sm4-pwd", @sm4.os_rand())
  let block = @byteutil.pem_decode(enc)
  assert_eq(block.type_, "SM4 ENCRYPTED KEY")
  assert_true(@byteutil.bytes_eq(@sm4.read_key_from_pem(enc, b"sm4-pwd"), key))
}
```

### SM2 密钥协商

```mbt check
///|
test "sm2 key exchange" {
  let (priv_a, rpriv_a) = (
    @sm2.generate_key(@sm2.os_rand()),
    @sm2.generate_key(@sm2.os_rand()),
  )
  let (priv_b, rpriv_b) = (
    @sm2.generate_key(@sm2.os_rand()),
    @sm2.generate_key(@sm2.os_rand()),
  )
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
  assert_true(@byteutil.bytes_eq(ka, kb)) // 协商出相同的 16 字节会话密钥
  assert_true(@byteutil.bytes_eq(s1a, s1b) && @byteutil.bytes_eq(s2a, s2b)) // 密钥确认值一致
}
```

## 构建与测试

使用 [MoonBit 工具链](https://www.moonbitlang.com/download)：

```bash
moon version --all  # 确认工具链版本
moon fmt --check    # 格式检查
moon check --deny-warn  # 类型 / 语法检查（警告视为错误）
moon test --deny-warn   # 运行测试
moon build --target wasm-gc  # 编译（wasm-gc 后端）
moon build --target native   # 编译（native 后端）
moon run cmd/sm2  # 运行 sm2 example 入口程序
moon run cmd/sm3  # 运行 sm3 example 入口程序
moon run cmd/sm4  # 运行 sm4 example 入口程序
```

## 许可证

本项目基于 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm) 移植，遵循 **Apache License 2.0**，与原项目许可证一致。详见 [LICENSE](LICENSE)。