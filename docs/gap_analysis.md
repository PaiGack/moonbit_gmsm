# 对标 `tjfoc/gmsm` 的功能差距分析

> 本文件记录本仓库（`PaiGack/gmsm`，MoonBit）与原项目
> [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm)（Go，Apache-2.0）之间的功能差距，
> 用于规划后续补齐顺序。
>
> - 对比基准：原项目 `master` 分支快照，统计口径为 **非测试文件**（`*.go` 排除 `*_test.go`）。
> - 本仓库口径：MoonBit 非测试源文件（`*.mbt` 排除 `*_test.mbt` / `*_wbtest.mbt`）。
> - 本文件是**静态 API 对照**结论；`docs/spec/` 下的规范文件描述实现契约，`docs/sm_vectors.md`
>   描述跨语言测试向量，两者与本文件互补。

## 0. 结论速览

原项目 23,371 行 Go 代码中，**核心算法（`sm2` / `sm3` / `sm4`）仅占 3,317 行（14%）**，
其余 20,054 行（86%）是围绕算法构建的外围生态：X.509 证书体系、GMTLS 握手、PKCS#12 密钥容器。

本仓库已经**完整移植了核心算法部分**，但外围生态**尚未开始**。

因此后续工作按「投入产出比」分为两档：

| 档位 | 内容 | 规模 | 依赖 |
| --- | --- | --- | --- |
| **A 档（补齐核心 API 的最后一公里）** | SM2 导出 `za` / 验签摘要接口 / `sm3_digest`；`byteutil` 增加 base64 + PEM + 通用 ASN.1 DER；`sm4` PEM 密钥读写 | 约 600–900 行 MoonBit | 无 |
| **B 档（补齐外围生态）** | `x509` 包 → `pkcs12` 包 → `gmtls` 包 | 约 1.5–2 万行 MoonBit | A 档全部 |

---

## 1. 覆盖率总表

| 原 Go 包 | Go 非测试 LOC | 本仓库对应 | MoonBit LOC | 状态 |
| --- | ---: | --- | ---: | --- |
| `sm2/` | 1,925 | `sm2/` | 2,071 | ✅ 核心算法齐全，**3 个导出缺失** |
| `sm3/` | 259 | `sm3/` | 329 | ✅ 完全对齐 |
| `sm4/` | 1,133 | `sm4/` + `byteutil/pkcs7` | 922 + 53 | ✅ 基本对齐，**缺 PEM** |
| `x509/` | 5,527 | — | — | ❌ **完全缺失** |
| `pkcs12/` | 1,641 | — | — | ❌ **完全缺失** |
| `gmtls/` | 12,886 | — | — | ❌ **完全缺失** |

> MoonBit 侧 `sm2` 反而比 Go 更长，是因为 Go 依赖 `math/big` 与 `golang.org/x/crypto/cryptobyte`，
> 而本仓库自带了 4 × 64-bit limbs 的大数实现（`sm2/bn.mbt`）与 Jacobian 点运算（`sm2/curve.mbt`），
> 并按 `docs/spec/spec_001_SM2.md` 的分层全部内联，无外部依赖。

---

## 2. 完全缺失的包

### 2.1 `x509` —— SM2 证书体系（5,527 行，最大缺口）

原项目 README 宣称的核心卖点基本都落在这个包里，本仓库目前**一个都没有**：

| 能力域 | 原 Go API | 说明 |
| --- | --- | --- |
| 证书生成 | `CreateCertificate`、`CreateCertificateToPem` | 以 SM2 私钥签发 SM2 证书 |
| 证书解析 | `ParseCertificate`、`ParseCertificates`、`ParseSm2CertifateToX509` | 解析 DER / PEM 证书 |
| 证书链 | `CertPool`、`NewCertPool`、`SystemCertPool`、`VerifyOptions`、`CertificateInvalidError`、`HostnameError`、`UnknownAuthorityError` | 证书链与校验错误模型 |
| 吊销 | `ParseCRL`、`ParseDERCRL`、`CreateRevocationList`、`RevocationList` | CRL |
| CSR | `CreateCertificateRequest`、`ParseCertificateRequest`、`CreateCertificateRequestToPem`、`ReadCertificateRequestFromPem`、`CertificateRequest` | 证书签名请求 |
| PEM 读写 | `ReadPrivateKeyFromPem`、`WritePrivateKeyToPem`、`ReadPublicKeyFromPem`、`WritePublicKeyToPem`、`ReadCertificateFromPem` | 密钥 / 证书 PEM 封装 |
| Hex 工具 | `ReadPrivateKeyFromHex`、`WritePrivateKeyToHex`、`ReadPublicKeyFromHex`、`WritePublicKeyToHex` | 十六进制裸密钥互转 |
| PKCS#8 | `MarshalSm2PrivateKey`、`MarshalSm2UnecryptedPrivateKey`、`MarshalSm2EcryptedPrivateKey`、`ParseSm2PrivateKey`、`ParsePKCS8UnecryptedPrivateKey`、`ParsePKCS8EcryptedPrivateKey`、`ParsePKCS8PrivateKey`、`PrivateKeyInfo`、`EncryptedPrivateKeyInfo` | RFC 5958 加密 PEM 的底层 |
| PKCS#7 | `ParsePKCS7`、`NewSignedData`、`PKCS7Encrypt`、`PKCS7EncryptSM2`、`DegenerateCertificate`、`SignedData`、`Attribute` | SM2 签名的 PKCS#7 封装 |
| PKIX 公钥 | `ParsePKIXPublicKey`、`MarshalPKIXPublicKey`、`ParseSm2PublicKey`、`MarshalSm2PublicKey` | 公钥序列化 |
| PKCS#1 | `ParsePKCS1PrivateKey`、`MarshalPKCS1PrivateKey` | 仅 RSA，优先级最低 |
| 签名算法 | `SignatureAlgorithm`、`Hash`、`RegisterHash`、`PublicKeyAlgorithm`、`KeyUsage`、`ExtKeyUsage` | 扩展 OID 体系 |

**前置依赖（必须先补）**：本仓库 `byteutil/asn1.mbt` 目前只有四个零散函数
（`encode_asn1_integer` / `encode_asn1_octet_string` / `encode_asn1_length` / `decode_asn1_length`），
**没有通用 ASN.1 DER 解析器与构造器，也没有 base64 与 PEM 编码**。`x509` 必须建立在这层之上。

### 2.2 `gmtls` —— GMTLS 1.3（12,886 行，工作量最大）

基于 TLS 1.3 的国密握手实现。除核心握手外还包含：

| 子项 | 说明 |
| --- | --- |
| `gmtls/` 握手核心 | `Client` / `Server` / `Dial` / `Listen` / `NewListener`、`Conn`、`Config`、`Certificate`、`ConnectionState`、会话票据与缓存 |
| 密码套件 | `cipher_suites.go`、`SignatureScheme`（含 SM2 签名方案）、`CurveID` |
| 国密扩展 | `gm_support.go` 的 `GMSupport` / `LoadGMX509KeyPairs` / `GMX509KeyPairs` / `GMX509KeyPairsSingle`（双证书：签名证书 + 加密证书） |
| 密钥协商 | `gm_key_agreement.go` |
| 自动切换 | `auto_switch_config.go` 的 `NewBasicAutoSwitchConfig`（国密 / 标准证书自动降级） |
| gRPC 凭据 | `gmcredentials/`（含 `echo/echo.pb.go`） |
| HTTP 客户端 | `http_client.go` 的 `NewHTTPSClient` / `NewAuthHTTPSClient` / `NewCustomHTTPSClient` |
| Web 服务端 | `websvr/websvr.go` |

> `gmtls` 依赖 `x509`（证书加载与校验），且需要 MoonBit 侧具备网络与 IO 能力，
> 建议放在整个路线图的**最后**。

### 2.3 `pkcs12` —— PKCS#12 密钥容器（1,641 行）

| 能力域 | 原 Go API |
| --- | --- |
| 容器编解码 | `Encode`、`Decode`、`DecodeAll`、`ToPEM` |
| 国密专用 | `SM2P12Encrypt`、`SM2P12Decrypt` |
| PKCS#8 底层 | `ParsePKCS8PrivateKey`、`MarshalECPrivateKey`、`MarshalPrivateKey` |
| 辅助算法 | `pbkdf.go`（PBKDF）、`mac.go`（HMAC/PBE）、`rc2.go`（RC2 块密码）、`safebags.go`（SafeBag / SafeContents） |

> 依赖 `x509`（需要解析证书链）。

---

## 3. 已有包内缺失的 API

### 3.1 SM2 —— 3 个导出 + 1 个接口抽象

| 原 Go 导出 | Go 位置 | 本仓库现状 | 影响 |
| --- | --- | --- | --- |
| `ZA(pub, uid) ([]byte, error)` | `sm2/sm2.go:443` | `za()` 私有（`sm2/primitives.mbt:32`） | 外部无法单独计算 Z 值；Z 值是 SM2 规范（GM/T 0003-2012）的**公开组成部分**，跨语言互操作需要 |
| `Verify(pub, hash, r, s) bool` | `sm2/sm2.go:224` | **无对应** | 只能验签「消息」，无法验签「已算好的摘要」。**这是 x509 验证证书签名（对 TBS 字节摘要验签）的刚需** |
| `PublicKey.Sm3Digest(msg, uid) ([]byte, error)` | `sm2/sm2.go:104` | `msg_hash()` 私有（`sm2/primitives.mbt:64`） | 外部无法取 e = SM3(ZA ‖ M) |
| `crypto.Signer` / `crypto.Verifier` 适配 | `sm2/sm2.go:76,84` | 由 `sm2_sign_der` / `sm2_verify_der` 部分替代 | 缺一个统一的「签名者」抽象，`x509` 签发时需要 |

> **与 `docs/spec/spec_003_idioms.md` 的关系**：该文把 `za` / `msg_hash` / `kdf` / `ke_x_hat`
> 列为「不应 `pub`」的内部步骤。本文件建议导出 `za`，二者并不冲突——
> `kdf` / `ke_x_hat` 确属内部实现，应保持私有；而 **Z 值是协议层的公开输出**（原 Go 版即导出），
> `sm3_digest` 与「验签摘要」同理，都属于「使用者可能需要的、可独立复用的协议原语」，
> 与「大数运算内部细节」性质不同。若采纳本文件的建议，
> 请同步在 `spec_003_idioms.md` 中标注这三项为有意保留的公开 API。

### 3.2 SM4 —— PEM 密钥读写

原项目 `sm4/utils.go` 自带一套 PEM 支持，本仓库 `sm4` 包完全没有：

| 原 Go API | 说明 |
| --- | --- |
| `type SM4Key []byte` | 密钥类型 |
| `ReadKeyFromPem(data, pwd)` | 从 PEM 读取密钥，`pwd` 非空时按 pem block 加密解密 |
| `ReadKeyFromPemFile(file, pwd)` | 同上，文件版本 |
| `WriteKeyToPem(key, pwd)` | 写出 PEM |
| `WriteKeyToPemFile(file, key, pwd)` | 同上，文件版本 |

> 依赖 `byteutil` 的 base64 + PEM 支持（见 §2.1 前置依赖）。

### 3.3 SM4 —— `padding` 子包（流式 IO 版）

原 `sm4/padding/` 提供基于 `io.Reader` / `io.Writer` 的流式填充：

| 原 Go API | 本仓库现状 |
| --- | --- |
| `NewPKCS7PaddingReader(in, blockSize)` | 无 |
| `NewPKCS7PaddingWriter(out, blockSize)` | 无 |
| `P7BlockEnc(encrypter, in, out)` | 无 |
| `P7BlockDecrypt(decrypter, in, out)` | 无 |

本仓库 `byteutil/pkcs7_pad` / `byteutil/pkcs7_unpad` 是**一次性**版本，功能上覆盖了绝大多数场景，
仅缺少流式读写形态。**优先级低**，待 `byteutil` 具备 IO 适配后再考虑。

### 3.4 SM3

无缺失。`New()`（`hash.Hash` 语义）、`Sm3Sum`、`SumMulti` 均已覆盖，
流式状态的 `write / sum / reset / size / block_size` 行为与 Go 对齐。

---

## 4. 已确认忠实移植、无需改动的部分

以下几处容易被误判为「缺陷」，实为**刻意对齐原版行为**：

| 项 | 说明 |
| --- | --- |
| SM4 CFB / OFB 只处理整块 | 原 Go 版 `Sm4CFB` / `Sm4OFB` 同样是 `len(inData)/16` 的整块循环，不处理尾部不满块。本仓库 [sm4/cipher.mbt](../sm4/cipher.mbt) 与之一致 |
| SM4-GCM 解密不校验 tag | 原 Go 版 `Sm4GCM` / `GCMDecrypt` 只返回 tag，由调用方自行比对。本仓库 `sm4_gcm` 行为一致，并已在 [sm4/cipher.mbt](../sm4/cipher.mbt) 注释中说明 |
| SM2 `Encrypt` 空明文死循环 | 原 Go 版 KDF 对长度 0 返回 `!ok`，`Encrypt` 会死循环。本仓库 `sm2` 的白盒测试已单独覆盖空明文场景（见 `baseline-go/README.md` 的说明） |

其余已覆盖且语义一致的能力：

- **SM2**：C1C3C2 与 C1C2C3 双密文排布、ASN.1 密文、`CipherMarshal` / `CipherUnmarshal`、
  `Compress` / `Decompress`、`KeyExchangeA` / `KeyExchangeB`、`SignDigitToSignData` / `SignDataToSignDigit`、
  `P256Sm2()` 曲线参数、`GenerateKey`、私钥推导公钥、点在曲线上判断。
- **SM3**：一次性摘要、多段拼接摘要、流式状态机。
- **SM4**：`NewCipher`（对齐 `cipher.Block`）、ECB / CBC / CFB / OFB、GCM、
  包级 `SetIV` / `IV` 默认向量。

---

## 5. 补齐路线图

### 阶段 A —— 核心 API 的最后一公里（无依赖，可立即开工）

| 序号 | 事项 | 位置 | 预估 |
| --- | --- | --- | --- |
| A1 | 导出 `za(x, y, uid) -> Bytes` | `sm2/primitives.mbt` | 5 行 |
| A2 | 新增 `sm2_verify_digest(pub, digest, r, s) -> Bool`（对应 Go `Verify`） | `sm2/sm2.mbt` | 约 60 行（复用现有验签骨架） |
| A3 | 新增 `sm2_digest(msg, uid) -> Bytes`（对应 Go `Sm3Digest`） | `sm2/sm2.mbt` | 约 15 行 |
| A4 | `byteutil` 增加 base64 编解码 | `byteutil/base64.mbt`（新） | 约 120 行 |
| A5 | `byteutil` 增加 PEM 封装 / 解析 | `byteutil/pem.mbt`（新） | 约 150 行 |
| A6 | `byteutil` 增加通用 ASN.1 DER 解析器与构造器 | `byteutil/asn1.mbt`（扩写） | 约 300–400 行 |
| A7 | `sm4` 增加 PEM 密钥读写（`sm4_key` 类型 + 4 个函数） | `sm4/utils.mbt`（新） | 约 80 行 |

> A2 是 `x509` 验签的**硬前置**：证书签名是对 TBS 字节的摘要验签，不走 `msg ‖ uid` 路径。

### 阶段 B —— `x509` 包（依赖 A5 / A6）

先做 SM2 子集：`Certificate` 解析与生成 → PEM 读写 → PKCS#8 → CSR → 证书链 / 校验 → PKCS#7。
RSA / PKCS#1 相关（`ParsePKCS1PrivateKey` 等）可最后考虑或直接不做。

### 阶段 C —— `pkcs12` 包（依赖 B）

### 阶段 D —— `gmtls` 包（依赖 A / B / C，且依赖网络栈）

---

## 6. 复现本分析

```sh
# 拉取原项目
git clone --depth 1 https://github.com/tjfoc/gmsm.git /tmp/gmsm_orig

# 各包非测试代码行数
cd /tmp/gmsm_orig
for d in sm2 sm3 sm4 x509 pkcs12 gmtls; do
  printf "%-8s %s\n" "$d" "$(find $d -name '*.go' ! -name '*_test.go' | xargs cat | wc -l)"
done

# 本仓库非测试代码行数
cd /workspace
find . -name '*.mbt' -not -path './_build/*' \
  -not -name '*_test.mbt' -not -name '*_wbtest.mbt' | xargs wc -l
```

本仓库侧的公开 API 以各包的 `pkg.generated.mbti` 为准（由 `moon info` 生成）。

---

## 7. 相关文档

- [`docs/spec/spec_001_SM2.md`](spec/spec_001_SM2.md) —— SM2 分层设计与 API 契约
- [`docs/spec/spec_002_SM4.md`](spec/spec_002_SM4.md) —— SM4 实现规范
- [`docs/spec/spec_003_idioms.md`](spec/spec_003_idioms.md) —— MoonBit 惯用法整改
- [`docs/sm_vectors.md`](sm_vectors.md) —— 跨语言测试向量（由 `baseline-go/` 的 Go oracle 生成）
- [`baseline-go/README.md`](../baseline-go/README.md) —— Go 参考 oracle 的工作流
