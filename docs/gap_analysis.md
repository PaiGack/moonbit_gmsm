# 对标 `tjfoc/gmsm` 的功能差距分析

> 本文件记录本仓库（`PaiGack/gmsm`，MoonBit）与原项目
> [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm)（Go，Apache-2.0）之间的功能差距，
> 用于规划后续补齐顺序。
>
> - 对比基准：原项目 `master` 分支快照，统计口径为 **非测试文件**（`*.go` 排除 `*_test.go`）。
> - 本仓库口径：MoonBit 非测试源文件（`*.mbt` 排除 `*_test.mbt` / `*_wbtest.mbt`）。
> - 本文件是**静态 API 对照**结论；`docs/spec/` 下的规范文件描述实现契约，`docs/sm_vectors.md`
>   描述跨语言测试向量，两者与本文件互补。

> **进度更新（2026-11-12）**：阶段 A（A1–A7）已完成，详见 §5「阶段 A 完成情况」。

## 0. 结论速览

原项目 23,371 行 Go 代码中，**核心算法（`sm2` / `sm3` / `sm4`）仅占 3,317 行（14%）**，
其余 20,054 行（86%）是围绕算法构建的外围生态：X.509 证书体系、GMTLS 握手、PKCS#12 密钥容器。

本仓库已经**完整移植了核心算法部分**，但外围生态**尚未开始**。

因此后续工作按「投入产出比」分为两档：

| 档位 | 内容 | 规模 | 依赖 |
| --- | --- | --- | --- |
| **A 档（补齐核心 API 的最后一公里）** | SM2 导出 `za` / 验签摘要接口 / `sm3_digest`；`byteutil` 增加 base64 + PEM + 通用 ASN.1 DER；`sm4` PEM 密钥读写 | 约 600–900 行 MoonBit | 无 |
| **B 档（补齐外围生态）** | 前置层 `byteutil/asn1` + `crypto` → `x509` → `pkcs12` → `gmtls` | 约 2.1–2.9 万行 MoonBit | A 档全部 + B1 |

> 阶段 A 中 **A6（通用 ASN.1 DER）未完成**，而 `x509` / `pkcs12` / `gmtls` 三者全部以它为地基。
> 因此实施规划（§6）把 A6 与配套的 `crypto` 辅助包拆成 B1，作为 B 档的第一步。

---

## 1. 覆盖率总表

| 原 Go 包 | Go 非测试 LOC | 本仓库对应 | MoonBit LOC | 状态 |
| --- | ---: | --- | ---: | --- |
| `sm2/` | 1,925 | `sm2/` | 2,071 | ✅ 核心算法齐全，**3 个导出缺失**（2026-11-12 已补齐 `za` / `sm3_digest` / `verify_digest`） |
| `sm3/` | 259 | `sm3/` | 329 | ✅ 完全对齐 |
| `sm4/` | 1,133 | `sm4/` + `byteutil/pkcs7` | 922 + 53 | ✅ 基本对齐（2026-11-12 已补齐 PEM 密钥读写，`padding` 流式版仍未做） |
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
**没有通用 ASN.1 DER 解析器与构造器**。`x509` 必须建立在这层之上。
（2026-11-12：base64 与 PEM 已补齐，DER 解析器仍待实现。）

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
| `ZA(pub, uid) ([]byte, error)` | `sm2/sm2.go:443` | ✅ `SM2PublicKey::za(uid)` | 已补齐 |
| `Verify(pub, hash, r, s) bool` | `sm2/sm2.go:224` | ✅ `sm2_verify_digest(pub, digest, r, s)` | 已补齐，满足 x509 验签前置 |
| `PublicKey.Sm3Digest(msg, uid) ([]byte, error)` | `sm2/sm2.go:104` | ✅ `SM2PublicKey::sm3_digest(msg, uid)` | 已补齐 |
| `crypto.Signer` / `crypto.Verifier` 适配 | `sm2/sm2.go:76,84` | 由 `sm2_sign_der` / `sm2_verify_der` 部分替代 | 缺一个统一的「签名者」抽象，`x509` 签发时需要 |

> **与 `docs/spec/spec_003_idioms.md` 的关系**：该文把 `za` / `msg_hash` / `kdf` / `ke_x_hat`
> 列为「不应 `pub`」的内部步骤。本文件建议导出 `za`，二者并不冲突——
> `kdf` / `ke_x_hat` 确属内部实现，应保持私有；而 **Z 值是协议层的公开输出**（原 Go 版即导出），
> `sm3_digest` 与「验签摘要」同理，都属于「使用者可能需要的、可独立复用的协议原语」，
> 与「大数运算内部细节」性质不同。若采纳本文件的建议，
> 请同步在 `spec_003_idioms.md` 中标注这三项为有意保留的公开 API。

### 3.2 SM4 —— PEM 密钥读写

原项目 `sm4/utils.go` 自带一套 PEM 支持，本仓库 `sm4` 包完全没有：

| 原 Go API | 本仓库对应 | 状态 |
| --- | --- | --- |
| `type SM4Key []byte` | `pub type SM4Key = Bytes` | ✅ |
| `ReadKeyFromPem(data, pwd)` | `read_key_from_pem(data : String, pwd : Bytes)` | ✅ |
| `ReadKeyFromPemFile(file, pwd)` | 无（核心库暂无 `fs`，由调用方读文件） | ⏳ |
| `WriteKeyToPem(key, pwd)` | `write_key_to_pem(key, pwd, random?)`（多一个 IV 随机源参数） | ✅ |
| `WriteKeyToPemFile(file, key, pwd)` | 无（同上） | ⏳ |

> 依赖 `byteutil` 的 base64 + PEM 支持（见 §2.1 前置依赖），两者均已补齐。

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

#### 阶段 A 完成情况（2026-11-12）

| 序号 | 事项 | 实际落地 | 状态 |
| --- | --- | --- | --- |
| A1 | 导出 Z 值 | `SM2PublicKey::za(uid) -> Bytes raise Sm2Error`（`sm2/sm2.mbt`），私有 `za()` 保持不变 | ✅ |
| A2 | 摘要验签 | `sm2_verify_digest(pub, digest, r, s)`，与 `sm2_verify` 共用 `verify_with_e` 内核 | ✅ |
| A3 | e = SM3(ZA ‖ M) | `SM2PublicKey::sm3_digest(msg, uid)`，`uid` 为空时同 Go 一样改用默认 uid | ✅ |
| A4 | base64 | `byteutil/base64.mbt`：`base64_encode` / `base64_decode` | ✅ |
| A5 | PEM | `byteutil/pem.mbt`：`pem_encode` / `pem_encode_simple` / `pem_decode` / `pem_decode_all`，支持 RFC 1423 头部 | ✅ |
| A6 | 通用 ASN.1 DER | **未做**：本轮只补 SM2 / SM4 相关能力，DER 解析器留给 `x509` 阶段一起设计 | ⏳ |
| A7 | SM4 密钥 PEM | `sm4/utils.mbt`：`read_key_from_pem` / `write_key_to_pem`（`SM4Key = Bytes`） | ✅ |

补充说明：

- A7 的口令加密格式与 gmsm 完全一致（`SM4 ENCRYPTED KEY` + `Proc-Type` / `DEK-Info`
  头部 + AES-256-CBC，密钥为口令补零到 32 字节），因此需要实现一个最小的
  AES-256（`sm4/aes.mbt`），并用 FIPS-197 附录 C.3 的已知答案做了单元测试。
- 「文件版本」的 `ReadKeyFromPemFile` / `WriteKeyToPemFile` 没有移植：当前工具链的
  核心库没有 `fs` 包，MoonBit 侧改为调用方自行读文件后传给上面两个函数。
- 新 API 都有跨语言测试向量：`sm2_za` / `sm2_digest_sign` 两组向量由
  `baseline-go` 的 oracle 生成（见 `baseline-go/full_api_test.go`）；SM4 加密 PEM
  之所以没有固定向量，是因为 gmsm 的 IV 取自 `crypto/rand.Reader`，无法在不同进程间复现，
  改为 MoonBit 侧「写→读」往返测试覆盖。
- 新增的 `sm2_verify_digest` 也让 §3.1 提到的 `x509` 验签硬前置得以满足。
- 工具链提示：本版本的 MoonBit 编译器中，在 `raise` 函数的 `for` / `while` **循环体内**
  直接 `raise`，会导致后续数值比较求值异常（表现为 `114 > 16` 之类的比较结果错误，
  且不报编译警告）。新增代码统一采用「循环内记录失败标志、循环之后统一抛出」的写法，
  例如 `sm4/utils.mbt` 的 `pkcs7_unpad_key`。

### 阶段 B —— `x509` 包（依赖 A5 / A6）

SM2 子集的最小闭环（B2）、完整能力（B3）与可选的 Go 兼容层（B4），详见 §6.5。
RSA / PKCS#1 / DSA / ECDSA 相关（`ParsePKCS1PrivateKey` 等）**不在移植范围**。

### 阶段 C —— `pkcs12` 包（依赖 B），见 §6.6

### 阶段 D —— `gmtls` 包（依赖 A / B / C，且依赖网络栈），见 §6.7

---

## 6. 实施规划：`x509` / `pkcs12` / `gmtls` 怎么落地

> 本节回答「这三个包应该怎么实现」。结论先给出：**不能把 2 万行 Go 一对一照抄**，
> 原实现建立在 Go 标准库（`crypto/x509`、`encoding/asn1`、`net/http`、`crypto/tls`）之上，
> 移植的本质是「用一个 MoonBit 版的 Go 标准库子集支撑起这三层」。
> 下面的拆解按依赖顺序给出层次、文件清单、API 映射与验收标准，
> 每一层都能**独立编译、独立测试**，不必等上层完成。

### 6.1 先算清楚：缺口规模与依赖

| 包 | Go 非测试 LOC | 直接依赖的 Go 标准库 | MoonBit 预计 LOC（×1.2–1.5） | 原测试 LOC |
| --- | ---: | --- | ---: | ---: |
| `x509/` | 5,527 | `crypto/x509`（含 `pkix`）、`encoding/asn1`、`crypto/{ecdsa,rsa,dsa,elliptic,aes,des,md5,sha1,sha256,sha512,hmac}`、`net`、`time` | 6,600–8,300 | 2,536 |
| `pkcs12/` | 1,641 | `crypto/des`、`crypto/sha1`、`crypto/hmac`、`encoding/asn1` | 2,000–2,500 | 3,662 |
| `gmtls/` | 12,886 | `crypto/tls` 全量改造、`crypto/{aes,des,rc4,sha1,sha256,hmac,subtle}`、`x/crypto/{curve25519,chacha20poly1305}`、`net`、`net/http` | 15,000–19,000 | 2,148 |
| **合计** | **20,054** | — | **约 2.4–3 万行** | 8,346 |

被引用的标准库函数频次（非测试代码，`grep '"crypto/'` 统计）：

- `x509/`：`ecdsa`×4、`elliptic`×3、`hmac`×3、`rsa`×7、`sha1`×5、`md5`×2、`sha256`×2、`aes`×2、`des`×2、`dsa`×1；
- `pkcs12/`：`des`×1、`sha1`×3、`hmac`×4、`md5`×2；
- `gmtls/`：`rsa`×10、`ecdsa`×10、`sha1`×3、`sha256`×3、`sha512`×2、`rc4`×1、`aes`×2、`des`×1、`hmac`×4。

**三个能砍掉的大头**（可省 30%–40% 工作量）：

1. **RSA / ECDSA / DSA / P-256/P-384/P-521 曲线**：国密链路只需要 SM2。`x509` 中 `parsePublicKey` /
   `checkSignature` / `signingParamsForPublicKey` 的 RSA·ECDSA·DSA 分支做成「识别 OID → 返回
   `UnsupportedAlgorithm`」，不做具体验签。`pkcs12/pkcs8.go` 的 `ecdsa` 分支同理。
2. **`GetCertificate` 的 `ToX509Certificate` / `FromX509Certificate`**（约 500 行、涉及 `crypto/x509` 四套结构互转）
   不移植；留一个 `to_stdlib_compatible_der()`（即 `cert.raw`）即可。
3. **`gmtls` 中的 TLS 1.0/1.1/1.2 全量握手与 `crypto/tls` 的 RSA/ECDHE/ChaCha20 套件**：只保留
   GM/T 0024 的国密套件（`0xE0xx`）与必要的 SM2 密钥交换。

### 6.2 分层架构与依赖图

```
                gmtls (B6)                      ← 依赖 net/io、x509、sm2/sm3/sm4
                  │
          pkcs12 (B5)                           ← 依赖 x509、crypto (DES/SHA1/HMAC)、asn1
                  │
               x509 (B2–B4)                     ← 依赖 asn1、sm2、crypto、byteutil(pem)
                  │
    crypto (B1b)  │  asn1 (B1a)                 ← 纯算法/编码，无业务依赖
        DES/RC4/SHA1/MD5/PBKDF2/PBKCS5/PKCS7-PBE, ASN.1 DER 编解码器
                  │
   sm2 / sm3 / sm4 / byteutil (已完成 A 档)      ← 唯一的地基
```

- **`asn1`（B1a）是全局咽喉**：`x509`、`pkcs12`、`gmtls`（握手消息、证书、扩展）全部走它。
- **`crypto`（B1b）** 名字上容易和已有 `sm2/sm3/sm4` 混淆，所以**不建独立顶层包**，而是挂在
  `byteutil` 下的子命名空间（`byteutil/des.mbt`、`byteutil/sha1.mbt` …），避免新增 `crypto` 顶层包与
  `moonbitlang/core` 的未来同名包冲突。
  > 若希望更清晰的分层，也可另建 `legacy_crypto/` 顶层包，`moon.pkg` 只有它自己能 import；二者等价，
  > 选一种即可。

### 6.3 B1a —— 通用 ASN.1 DER 编解码器（前置，约 1,100–1,300 行）

文件：`byteutil/asn1.mbt`（改写，保留现有 4 个函数做向后兼容）+ `byteutil/asn1_builder.mbt`（新）。

设计上**放弃 Go `encoding/asn1` 的反射风格**，改成 MoonBit 惯用的三件套：

| Go 能力 | 对应设计 |
| --- | --- |
| `asn1.Unmarshal(der, &out)` 反射出结构体 | **`DerReader`** 游标式解析：`read_sequence()` / `read_integer()` / `read_oid()` / `read_octet_string()` / `read_bit_string()` / `read_utf8_string()` / `read_bmp_string()` / `read_ia5_string()` / `read_utc_time()` / `read_generalized_time()` / `read_explicit(n)` / `read_raw()` / `peek_tag()` / `skip()` / `end()` |
| `asn1.Marshal` | **`DerBuilder`** 构建器：`sequence(fn)` / `integer(bytes)` / `oid([1,2,840,…])` / `octet_string(..)` / `bit_string(..)` / `null()` / `utf8_string(..)` / `bmp_string(..)` / `ia5_string(..)` / `utc_time(..)` / `generalized_time(..)` / `explicit(n, fn)` / `raw(..)` |
| `asn1.RawValue` | `DerElement { tag : UInt8, is_constructed : Bool, content : Bytes, raw : Bytes }` |
| `asn1.ObjectIdentifier` | `Oid`（`Array[UInt32]`），带 `to_string` / `from_string`，`Eq`/`Hash` 实现 |
| `pkix.AlgorithmIdentifier` | x509 包内普通结构体 `AlgorithmIdentifier { algorithm : Oid, parameters : Bytes }` |
| `asn1.StructuralError` | `DerError` suberror：`Truncated` / `UnexpectedTag` / `TrailingData` / `InvalidLength` / `InvalidInteger` / `InvalidOid` |
| `ber2der`（`x509/ber.go`，248 行） | `byteutil/asn1_ber.mbt`：BER 不定长与构造类型展开，PKCS#7 / S/MIME 需要，随 B4 一起做 |
| 大整数：Go 用 `math/big`，x509 用 `asn1.Integer` | 复用 `sm2/bn.mbt` 的 256 位大数？**不**：证书序列号、RSA 公钥可达 2048–4096 位。用 `sm2/bn` 不够，需在 `byteutil` 提供 `BigInt` 最小的「非负大整数」类型（比较 / 加减 / 乘 / 模 / 转字节），约 300 行；如果控制范围为 SM2 证书（序列号 ≤ 256 位），可临时用 `Array[UInt64]` 变长表示。**推荐直接写变长 `BigInt`**，避免后续补丁。 |

时间类型：Go 用 `time.Time`；MoonBit 核心库没有完整时间库，ASN.1 时间在 `x509` 里主要做
「DER 字节 ↔ `DateTime` 结构体」的转换。建议定义 `pub struct DateTime { year, month, day, hour, minute, second, is_utc : Bool }`，
放在 `x509/` 包内（不急于做 timestamp 计算，证书校验的 `NotBefore` / `NotAfter` 用 `DateTime` 比较即可）。

**验收标准**：

- 单元测试：RFC 5280 附录 A 的证书 DER、PKCS#7 样例、`Go asn1.Marshal` 生成的向量（通过 `baseline-go` 输出 JSON）；
- 往返测试：任意 Go `asn1.Marshal` 产物能被 `DerReader` 读出且字段一致；
- `moon test` 全部通过，`moon info` 无意外 diff。

### 6.4 B1b —— 遗留密码算法辅助（约 600–900 行）

只在 `x509` 的 PKCS#8/PKCS#7、`pkcs12` 的 PBE、`gmtls` 的旧 TLS 套件里使用。**按需引入、逐个验收**：

| 算法 | 使用方（源文件） | MoonBit 文件 | 预估 | 优先级 |
| --- | --- | --- | ---: | --- |
| SHA-1 | x509/pkcs8.go、pkcs12/pbkdf.go、gmtls/prf.go | `byteutil/sha1.mbt` | 180 | **P0**（PKCS#12 / PKCS#5 必需） |
| MD5 | x509/pkcs8.go（`PBES1`）、pkcs12/crypto.go | `byteutil/md5.mbt` | 180 | P2（仅 PBES1 兼容） |
| HMAC（泛型） | x509/pkcs8.go、pkcs12/mac.go、gmtls/conn.go | `byteutil/hmac.mbt`（`hmac_sha1`、`hmac_sm3`） | 120 | **P0** |
| PBKDF2（HMAC-SHA1/SHA256） | x509/pkcs8.go | `byteutil/pbkdf2.mbt` | 120 | **P0** |
| PKCS#5 PBES2 + AES-CBC | x509/pkcs8.go | `byteutil/pbes2.mbt`（复用 `sm4/aes.mbt` 的内部函数，或提升为 `byteutil/aes.mbt`） | 150 | **P0** |
| PBES1 + DES-CBC | x509/pkcs8.go（仅旧格式读） | `byteutil/pbes1.mbt` + DES | 250 | P3 |
| DES / 3DES | pkcs12/crypto.go（3DES 为默认 PBE） | `byteutil/des.mbt` | 300 | **P1**（PKCS#12 必需） |
| RC2-40/128 | pkcs12/rc2.go、crypto.go（旧 Windows/OpenSSL 容器） | `byteutil/rc2.mbt`（含 256 字节 π 表） | 250 | P2（读兼容） |
| RC4 | gmtls/cipher_suites.go | `byteutil/rc4.mbt` | 80 | P3（国密链路不用） |
| SHA-256 / SHA-512 | gmtls/prf.go | — | — | **不做**（国密 PRF 用 SM3） |

> **复用已有代码**：`sm4/aes.mbt` 已有 AES-256 密钥扩展与加密块、CBC raw 加解密，
> 只需把 `aes256_expand_key` / `aes256_encrypt_block` / `aes256_cbc_*_raw` 提升到
> `byteutil/aes.mbt`（或在 `sm4/utils.mbt` 中加 `pub(crate)` 风格的导出），供 PBES2 复用。

### 6.5 B2–B4 —— `x509` 包（分三步，约 6.6–8.3k 行）

#### B2：SM2 证书最小闭环（约 2,800–3,500 行）

**目标**：能「生成自签 SM2 证书 → 写成 PEM → 读回 → 解析出字段 → 验签 → PKCS#8 私钥加解密」，
端到端与 `openssl` / Go 的证书互通。

| 文件 | 内容 | 预处理 |
| --- | --- | --- |
| `x509/types.mbt` | `Certificate`、`CertificateRequest`、`Name`、`AttributeTypeAndValue`、`AlgorithmIdentifier`、`PublicKeyAlgorithm` / `SignatureAlgorithm` 枚举、`KeyUsage` / `ExtKeyUsage` 位标志、`UnhandledCriticalExtension`、`InsecureAlgorithmError` 等错误类型 | 从 `x509.go` 的 `type (...) struct` 抽 |
| `x509/oids.mbt` | OID 常量：`oidSignatureSM2WithSM3 = 1.2.156.10197.1.501`、`oidSignatureWithSM3 = 1.2.156.10197.1.504`（SM3-with-RSA）、`oidPublicKeyECDSA = 1.2.840.10045.2.1`（SM2 复用它 + sm2p256v1 曲线 OID `1.2.156.10197.1.301`）、`oidNamedCurveP256SM2`、X.509 v3 扩展 OID 等 | 从 `x509.go` 的 `oid*` 变量抄 |
| `x509/parse.mbt` | `ParseCertificate` / `ParseCertificates`：TBS 结构 `tbsCertificate` → `Certificate`，扩展解析（`basicConstraints`、`keyUsage`、`extKeyUsage`、`SAN`、`subjectKeyId`、`authorityKeyId`） | `x509.go:1250` `parseCertificate` 约 260 行 |
| `x509/create.mbt` | `CreateCertificate`：`buildExtensions`（约 180 行）+ TBS 组装 + SM2 签名（SM2 不是 digest-then-sign，而是 `ZA‖M`；见 6.5.1） | `x509/utils.go:176` + `x509.go:1629` |
| `x509/pem.mbt` | `ReadCertificateFromPem` / `WriteCertificateToPem` / `ReadPrivateKeyFromPem` / `WritePrivateKeyToPem` / `ReadPublicKeyFromPem` / `WritePublicKeyToPem` | `x509/utils.go:18–160`，PEM 部分复用 `byteutil/pem.mbt` |
| `x509/hex.mbt` | `Read/Write{Private,Public}KeyFromHex` | `x509/utils.go:71–130`，30 行 |
| `x509/pkcs8.mbt` | `ParseSm2PrivateKey` / `ParseSm2PublicKey` / `MarshalSm2PublicKey` / `ParsePKIXPublicKey` / `MarshalPKIXPublicKey` / `MarshalSm2PrivateKey`（含口令） | `x509/pkcs8.go` 371 行 → 约 500 行 |

**6.5.1 SM2 证书签名的特殊之处（最容易踩坑）**

Go 的 `crypto.Signer.Sign(rand, digest, opts)` 对 ECDSA 是「对摘要签名」，而 SM2 签名需要
`e = SM3(ZA ‖ M)`。gmsm 的 `sm2.PrivateKey.Sign` 把传入的 `msg`（即 TBS 字节）原样交给
`Sm2Sign`，由 `Sm2Sign` 自己算 ZA 与摘要。因此移植时：

- 签发侧直接调用 `sm2_sign_der(priv, tbs_bytes, default_uid, random)`；
- 验签侧直接调用 `sm2_verify_der(pub, tbs_bytes, sig)`；
- **不要**走 `sm2_verify_digest`（那是给外部已算好 ZA‖M 摘要的场景准备的）。
- 证书 `signatureAlgorithm` = `1.2.156.10197.1.501`（SM2-with-SM3），`subjectPublicKeyInfo.algorithm` =
  `ecPublicKey` + `sm2p256v1`。

**跨语言验收（B2）**：在 `baseline-go/` 增加 `x509_oracle_test.go`，用 `gmsm/x509` 生成固定密钥的
自签证书并输出到 `docs/sm_vectors.json`；MoonBit 侧测试用**同一私钥、同一 TBS 模板**重建证书，
断言 DER 字节与 Go 输出**逐字节一致**（SM2 签名 k 值不确定，因此改为比较「去掉签名值后的 TBS 字节」一致，
再互相验签通过）。另外用 `openssl x509 -in cert.pem -text` 做人工抽查。

#### B3：证书链、CRL、CSR、PKCS#7（约 2,800–3,500 行）

| 文件 | 内容 | 原文件 |
| --- | --- | --- |
| `x509/cert_pool.mbt` | `CertPool`、`new_cert_pool`、`add_cert`、`append_certs_from_pem` | `cert_pool.go` 229 行 |
| `x509/verify.mbt` | `verify(cert, opts)`、`verify_hostname`、错误模型（`CertificateInvalidError`/`HostnameError`/`UnknownAuthorityError`/`SystemRootsError`）、`match_hostnames`、KeyUsage 链校验 | `verify.go` 568 行；`SystemCertPool` 在无文件系统的 MoonBit 环境返回「无系统根」 |
| `x509/crl.mbt` | `ParseCRL` / `ParseDERCRL` / `CreateRevocationList` / `RevocationList` | `x509.go:1917–2100` |
| `x509/csr.mbt` | `CreateCertificateRequest` / `ParseCertificateRequest` / `CheckSignature` / PEM 读写 | `x509.go:2144–2350`、`utils.go:133–150` |
| `x509/pkcs7.mbt` | `PKCS7`、`SignedData`、`ParsePKCS7`、`NewSignedData`、`AddSigner`、`Verify`、`DecryptSM2`、`PKCS7EncryptSM2`、`DegenerateCertificate`、`Attribute` | `pkcs7.go` 1075 行 |
| `x509/ber.mbt` | `ber2der`（PKCS#7 常见 BER 不定长） | `ber.go` 248 行 |

`Verify` 是最复杂的部分：Go 版依赖 `time.Now()` 与系统根证书。MoonBit 侧设计为
`verify(cert, opts : VerifyOptions { roots, current_time : DateTime, dns_name, key_usages, ... })`，
**把当前时间显式传入**（便于测试与快照），不隐式读时钟。

#### B4：Go 兼容层（可选，约 400 行）

`ParseSm2CertifateToX509`、`ToX509Certificate` / `FromX509Certificate`、`signingParamsForPublicKey`
中的 RSA/ECDSA 分支、`ParsePKCS1PrivateKey` 等。**默认不做**，只在需要与 Go 的 `crypto/x509` 结构体互转时再补。

**不做清单（x509）**：RSA / ECDSA / DSA 验签与签发；`pkix` 包全量结构；`CGO`；`SystemCertPool` 的系统根读取
（MoonBit 无 `fs`）；`time.Time` 的全时区语义。

### 6.6 B5 —— `pkcs12` 包（约 2,000–2,500 行）

依赖 B1b 的 SHA-1 / 3DES / HMAC、B2 的 x509 解析。

| 文件 | 内容 | 原文件 |
| --- | --- | --- |
| `pkcs12/pfx.mbt` | `PFX` / `AuthSafe` / `SafeBag` / `SafeContents` / `EncryptedContentInfo` 结构体与 ASN.1 映射 | `pkcs12.go` 596 行 |
| `pkcs12/pbkdf.mbt` | RFC 7292 附录 B.2 的 PKCS#12 KDF（SHA-1，u/v 参数化） | `pbkdf.go` 170 行 |
| `pkcs12/mac.mbt` | `hmac_sha1` 校验 + 生成（`MacData`） | `mac.go` 59 行 |
| `pkcs12/crypto.mbt` | `pbeWithSHAAnd3KeyTripleDESCBC`（默认）、`pbeWithSHAAnd40BitRC2CBC`（旧容器读） | `crypto.go` 170 行 + `rc2.go` 274 行 |
| `pkcs12/safebags.mbt` | `decodePkcs8ShroudedKeyBag` / `encodePkcs8ShroudedKeyBag` / `decodeCertBag` / `encodeCertBag` | `safebags.go` 97 行 |
| `pkcs12/bmp_string.mbt` | BMPString（UTF-16BE）编解码，口令与 friendlyName 用 | `bmp-string.go` 50 行 |
| `pkcs12/pkcs8.mbt` | `parse_pkcs8_private_key` / `marshal_private_key` / `marshal_ec_private_key`（只保留 SM2 / EC 分支） | `pkcs8.go` 202 行 |
| `pkcs12/pkcs12.mbt` | `encode(private_key, cert, ca_certs, password)` / `decode` / `decode_all` / `to_pem` | `pkcs12.go:115–530` |
| `pkcs12/sm2_p12.mbt` | `SM2P12Encrypt` / `SM2P12Decrypt`（文件版改为返回 `Bytes`，由调用方写文件） | `pkcs12.go:560–596` |

**验收（B5）**：用 Go oracle 生成固定口令、固定盐/迭代次数的 `.p12`（MoonBit 侧允许注入盐以复现），
断言 `decode` 能读出相同私钥与证书；反方向由 MoonBit `encode` → Go `pkcs12.Decode` 验证；
再用 `openssl pkcs12 -in x.p12 -nodes` 做人工抽查。

### 6.7 B6 —— `gmtls` 包（约 15,000–19,000 行）

**这是最大的包，也是唯一强依赖「网络 + 并发 + 流式 IO」的包**，需要先补齐 MoonBit 运行时的能力假设：

1. **IO 抽象**：当前工具链的核心库已有 `moonbitlang/core/async`（含 `io`、`socket`、`tls`、`fs` 子包），
   先做一个 `gmtls/io.mbt`，定义 `pub(open) trait Read` / `Write` / `Close`（`async fn`），`Conn` 持有 `Read`+`Write`；
   另提供**内存版** `BufferRead` / `BufferWrite`，让握手逻辑与 socket 解耦、可被单元测试驱动。
   （这同时让 §3.2/§3.3 中「文件版」与「流式 padding」API 的补做变得可行。）
2. **并发**：TLS 记录层状态机（`conn.go` 1379 行）在 Go 里由 `sync.Mutex` 保护；MoonBit 侧可优先用
   核心库的 `async/mutex`，但首版建议做**单连接单任务**状态机，把并发安全留到后续。
3. **协议版本**：只做 GM/T 0024（`VersionGMSSL = 0x0101`）；`auto_switch_config` 的「国密/标准自动降级」
   需要标准 TLS 1.2，**默认不做**（列为可选）。

分阶段：

| 子阶段 | 内容 | 文件 | 预估 |
| --- | --- | --- | ---: |
| B6.1 | 常量与配置：`Config`、`Certificate`、`ConnectionState`、`GMSupport`、双证书 `GMX509KeyPairs`、`VersionGMSSL`、套件号 `0xE011/0xE013/0xE051/0xE053` | `common.mbt`、`gm_support.mbt`（`common.go` 1021 + `gm_support.go` 489） | 1,500 |
| B6.2 | PRF（`prf12` + SM3、`finishedHash`）、握手消息编解码（`handshake_messages.go` 1566 行、`gm_handshake_messages.go` 122 行） | `prf.mbt`、`handshake_messages.mbt` | 2,200 |
| B6.3 | 密钥交换：SM2 ECDHE（`gm_key_agreement.go` 451 行，复用 `sm2.key_exchange_a/b`）、签名认证（`auth.go`） | `key_agreement.mbt`、`auth.mbt` | 900 |
| B6.4 | 握手客户端/服务端（单证书 + 双证书，共 4 个文件 2712 行） | `handshake_client.mbt`、`handshake_server.mbt`、`gm_handshake_*` | 3,800 |
| B6.5 | 记录层：`Conn`（1379 行）、alert、ticket、会话缓存 | `conn.mbt`、`alert.mbt`、`ticket.mbt` | 2,200 |
| B6.6 | 门面：`client` / `server` 构造、`dial` / `listen` / `new_listener` | `tls.mbt`、`simple_round_trip.mbt` | 700 |
| B6.7 | （不移植）`gmcredentials`（gRPC，依赖 `google.golang.org/grpc`）、`http_client.go` / `websvr`（依赖 `net/http`） | — | 0 |

**验收（B6）**：
- 用 `baseline-go/` 中的 gmsm TLS 服务端 + MoonBit 客户端互连（或反过来），在本地回环完成一次
  GMTLS 1.1 握手并交换应用数据；
- 记录层与握手消息用 Go oracle 生成固定字节流做单测（握手消息可以确定性构造成字节向量）；
- 双证书（签名证书 + 加密证书）必须覆盖，这是国密合规的关键。

### 6.8 推荐实施顺序与里程碑

| 里程碑 | 内容 | 依赖 | 预计工作量（人日） | 可交付成果 |
| --- | --- | --- | ---: | --- |
| **M0** | B1a：`asn1` DER 编解码 + `BigInt` + `DateTime` | 无 | 8–10 | `byteutil/asn1` 单测 + Go 向量 |
| **M1** | B1b：SHA-1 / HMAC / PBKDF2 / PBES2-AES | M0 | 5–7 | `x509` 口令加密所需的密码学就绪 |
| **M2** | B2：`x509` SM2 最小闭环（生成/解析/PEM/PKCS#8） | M0、M1 | 15–20 | 自签证书端到端，与 Go / openssl 互通 |
| **M3** | B3：证书链、CSR、CRL、PKCS#7（含 BER） | M2 | 12–15 | 完整 `x509`（SM2 子集） |
| **M4** | B1b 补 DES/3DES/RC2 + B5：`pkcs12` | M3 | 10–12 | `.p12` 与 Go / openssl 互通 |
| **M5** | B6.1–B6.6：`gmtls` 握手与记录层 | M3（+ 网络层） | 35–45 | 本机 GMTLS 互通握手 |
| **合计** | — | — | **约 85–110 人日** | — |

**先做什么的建议**：如果只有一个迭代的预算，就先做 **M0 + M2**——`x509` 的「SM2 证书生成 / 解析 / PEM / PKCS#8」
是原项目最有辨识度的卖点，也是 `pkcs12`、`gmtls` 的共同地基。

### 6.9 工程约定（三个包都要遵守）

- **目录**：与 Go 一一对应（`x509/`、`pkcs12/`、`gmtls/`），每个目录一个 `moon.pkg`；
  MoonBit 的包不能有环依赖，因此 `x509` 里的 `pkcs7`、`verify` 都放在同一个包内（规则同 Go）。
- **错误模型**：Go 用 `error`，MoonBit 用 `suberror`（如 `X509Error`、`Pkcs12Error`、`GmtlsError`），
  每个包导出自己的错误类型，与现有 `Sm2Error` / `SM4Error` 保持一致。
- **公开 API**：一律 `pub fn`，参数风格与现有包一致（`Bytes`、`Bool`、`Int32` 显式传入）；
  Go 的「指针 + nil」语义改为 MoonBit 的 `Option[T]`。
- **IO / 文件**：核心库无 `fs`，`ReadKeyFromPemFile` 这类「文件版」API 改为接受 `Bytes` 或 `String`；
  由 `cmd/` 里的可执行示例负责读写文件。
- **测试策略**（与 A 档一致）：
  1. `baseline-go/` 增加 `x509_oracle_test.go`、`pkcs12_oracle_test.go`、`gmtls_vectors_test.go`，输出到 `docs/sm_vectors.json`；
  2. MoonBit 侧 `*_test.mbt` 直接加载向量断言；
  3. 签名类输出不确定的场景（SM2 签名、PKCS#12 随机盐）改「结构一致 + 双向验签」或「注入固定随机源」来复现；
  4. 每个里程碑结束都要 `moon info && moon fmt && moon test`。
- **常量与坑位**：沿用 §5 记录的「`raise` 函数循环体内直接 `raise` 会求值异常」的规避写法；
  ASN.1 解析器的递归深度要设上限（防恶意证书栈溢出），长度字段要校验不超过输入剩余长度。
- **许可**：`x509/`、`pkcs12/`、`gmtls/` 均改编自 Go 标准库 / `gmsm`，需在文件头保留
  Apache-2.0 / BSD-3-Clause 的版权声明（`pkcs12/rc2.go` 为 MIT）。

---

## 7. 复现本分析

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

## 8. 相关文档

- [`docs/spec/spec_001_SM2.md`](spec/spec_001_SM2.md) —— SM2 分层设计与 API 契约
- [`docs/spec/spec_002_SM4.md`](spec/spec_002_SM4.md) —— SM4 实现规范
- [`docs/spec/spec_003_idioms.md`](spec/spec_003_idioms.md) —— MoonBit 惯用法整改
- [`docs/sm_vectors.md`](sm_vectors.md) —— 跨语言测试向量（由 `baseline-go/` 的 Go oracle 生成）
- [`baseline-go/README.md`](../baseline-go/README.md) —— Go 参考 oracle 的工作流
