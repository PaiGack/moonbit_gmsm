# SM2 MoonBit 移植规范

> 本文件描述 `paigack/gmsm/sm2` 包的实现规划、API 契约、测试数据与测试方案。
> 实现目标：与 Go 生态中的 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm)（Apache-2.0）按
> `gmsm/sm2/sm2.go`、`gmsm/sm2/p256.go`、`gmsm/sm2/utils.go`、`gmsm/sm2/sm2_test.go`
> 在功能与测试向量上对齐。

## 全局规则

- go 版本的 tjfoc/gmsm gmsm 不需要看 github 的远端代码库，代码就在 gmsm 里面

## 1. 范围与目标

### 1.1 覆盖范围

参照 `gmsm/sm2/sm2.go` 暴露的全部公开能力（不含 CGo / `crypto.Signer` 适配层）：

| 能力域 | gmsm 函数 | 本包对应 API |
| --- | --- | --- |
| 曲线与点 | `P256Sm2`、`IsOnCurve`、`Add`、`Double`、`ScalarMult`、`ScalarBaseMult` | `sm2_p256()`、`SM2Point` 上的方法 |
| 密钥对 | `GenerateKey`、`Public()` | `generate_key(random)`、`derive_public_key(d)` |
| 签名（内部 r,s） | `Sm2Sign`、`Sm2Verify`、`Sm3Digest` | `sm2_sign(...)`、`sm2_verify(...)` |
| 签名（ASN.1 DER） | `SignDigitToSignData`、`SignDataToSignDigit` | `sm2_sign_der(...)`、`sm2_verify_der(...)` |
| 加解密 | `Encrypt`、`Decrypt`（C1C3C2 / C1C2C3） | `sm2_encrypt(...)`、`sm2_decrypt(...)` |
| 加解密（ASN.1） | `EncryptAsn1`、`DecryptAsn1`、`CipherMarshal`、`CipherUnmarshal` | `sm2_encrypt_asn1(...)`、`sm2_decrypt_asn1(...)` |
| 密钥协商 | `KeyExchangeA`、`KeyExchangeB`、`keXHat`、`ZA` | `key_exchange_a/b(...)`、`ke_x_hat(x)` |
| 公钥压缩 | `Compress`、`Decompress` | `compress_point(p)`、`decompress_point(b)` |
| 辅助 | `kdf`、`zeroByteSlice`、`ZA`、`msgHash` | `kdf(...)`、`za(pub, uid)` |

### 1.2 非目标

- 不实现 `crypto.Signer` / `crypto.Decrypter` / `crypto.Hash` 等 Go 接口适配（MoonBit 没有等价接口契约）；
- 不做侧信道（constant-time）保证；首版以「正确性 + 与 gmsm 互操作」为优先；
- 不实现 `gmtls` / `x509` / `pkcs12`（这些属于 SM2 之外的 TLS/X.509 链）。

### 1.3 标准依据

- GM/T 0003-2012《SM2 椭圆曲线公钥密码算法》（第 1 部分总则、第 2 部分数字签名、第 3 部分密钥交换、第 4 部分公钥加密）；
- GB/T 32918 系列（与 GM/T 0003 等同采用）；
- SM2 实施参考：`tjfoc/gmsm/sm2`。

## 2. 架构分层

按依赖方向自下而上 4 层。每层都用独立文件组织，对应 `sm2/` 包内文件命名：

```
sm2/
├── bn.mbt          // 层 1：Fp 大数与模运算（4×64-bit limbs，复用 SM2 素数快速约简）
├── curve.mbt       // 层 1.5：曲线常量、Jacobian 点、点运算、IsOnCurve
├── sm3.mbt         // （已存在）SM3 摘要
├── primitives.mbt  // 层 3：ZA / KDF / keXHat / msgHash
├── sm2.mbt         // 层 4：高层 API（密钥、签名、加解密、密钥协商、压缩）
├── sm2_wbtest.mbt  // 白盒测试
├── sm2_spec.mbt    // （可选）spec.mbt 类型声明（若采用 spec-driven 工作流）
└── moon.pkg        // 依赖：moonbitlang/core/bytes
```

> 现有 `sm2/sm2.mbt` 与 `sm2/sm3.mbt` 是「占位」实现（`derive_public_key` 返回基点、`sm2_sign` 写回 `e` 当 r/s、`sm2_verify` 永远 `true`、`sm2_encrypt` 仅复制明文）。本规范将它们替换为真实算法，并把签名 / 验证 / 加解密 / 密钥协商补齐。

### 2.1 层 1：大数与 Fp

256 位素数 `p`：

```
p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
  = 2^256 − 2^224 − 2^96 + 2^64 − 1
```

> **注意**：SM2 素数与 NIST P-256 素数虽然最终数值同为 256-bit，但二进制结构不同 —— P-256 的素数是 `2^256 − 2^224 + 2^192 + 2^96 − 1`（符号与 2^192 项都不同）。**不能直接复用** P-256 的快速约简公式（详见 §2.1.1）。

本规范采用 4 个 64-bit 字的小端字序（[low..high]），所有函数都对 4 字数组原地操作；字节 I/O 走大端。

> 与 gmsm 用 9 个 `uint32` 交替 29-bit / 28-bit 字的内部表示（见 `gmsm/sm2/p256.go:58` `sm2P256FieldElement [9]uint32`）相比，本规范用 4 × 64-bit 是为了可读性与 MoonBit 的 `UInt64` 路径；性能上比 gmsm 略差但足够覆盖签名/加解密/密钥协商三种工作负载。

**核心函数（`bn.mbt`）**：

| 函数 | 签名 | 说明 |
| --- | --- | --- |
| `bn_zero(r)` | `(FixedArray[UInt64]) -> Unit` | 全 0 |
| `bn_copy(dst, src)` | `(FA[U64], FA[U64]) -> Unit` | 4 字复制 |
| `bn_from_bytes(r, b, off)` | `(FA[U64], Bytes, Int) -> Unit` | 32 字节大端 → 4 字 |
| `bn_to_bytes(r)` | `(FA[U64]) -> Bytes` | 4 字 → 32 字节大端 |
| `bn_is_zero(a) / bn_eq / bn_lt / bn_gt` | `Bool` | 256-bit 比较 |
| `bn_add(r, a, b) -> UInt` | 带进位加（r=a+b，return carry） |
| `bn_sub(r, a, b) -> UInt` | 带借位减 |
| `bn_addmod_p(r, a, b)` | `Fp` 模加（用 `p` 减法做条件减） |
| `bn_submod_p(r, a, b)` | `Fp` 模减 |
| `bn_mul(r, a, b)` | schoolbook 4×4 → 8 字 |
| `bn_sqr(r, a)` | 同上但共用 a |
| `bn_mod_p(r, s)` | 256→256 模 p 约简（SM2 专用路径，详见 §2.1.1） |
| `bn_modmul_p(r, a, b)` | 调 `bn_mul` 后 `bn_mod_p` |
| `bn_modsqr_p(r, a)` | 同上 |
| `bn_modinv_p(r, a)` | Fermat：`a^(p-2) mod p`（平方-乘 256 轮）；后续可换为 `addchain` |
| `bn_mod_n(r, a)` | 模曲线阶 n。n < 2^256 但与 NIST P-256 的 n 不同，**不**复用 P-256 约简路径；采用「算到 512-bit 再用 `n` 减几次」朴素方案（gmsm 同款） |
| `bn_rand_k(random) -> FA[U64]` | 1 ≤ k ≤ n-1（签名随机数，**不是**私钥生成；用 MoonBit `random` 接口；缺省时用 `Rand::chacha8`）。算法：`k = (rand_bytes mod (n-1)) + 1`（与 gmsm `sm2.go:622-637` `randFieldElement` 一致） |

#### 2.1.1 模 `p` 快速约简（4 × 64-bit 路径）

> **重要：本规范不直接复用 NIST P-256 的约简公式。SM2 素数与 P-256 素数最终值不同（虽然都是 256-bit），等价关系式更是不同 ——**

SM2 素数 `p = 2^256 − 2^224 − 2^96 + 2^64 − 1` 满足：

```
2^256 ≡ 2^224 + 2^96 − 2^64 + 1   (mod p)
```

NIST P-256 的等价关系式 `2^256 ≡ 2^224 − 2^192 − 2^96 + 1` 与上式符号不同，**不能直接照抄** Go 标准库 `p256.go` 的约简公式。

实现方案（按优先级，本规范推荐 P2）：

| 方案 | 路径 | 性能 | 风险 |
| --- | --- | --- | --- |
| **P1** | 改用 gmsm 同款 9 × 29-bit 字（`[9]uint32` 交替 29/28-bit）路径 | 高 | 移植成本大、需重写所有 bn.* 与点运算 |
| **P2（推荐）** | 4 × 64-bit 路径 + 通用 Barrett 约简（先减 2^256 倍数，再做 2 次条件减 `p`） | 中（比 gmsm 慢 ~2×） | 实现简单、矩阵项少 |
| **P3** | 4 × 64-bit 路径 + 自推导的快速约简（见下） | 高 | 公式须经独立单元测试验证 |

**P2 详细步骤**（`bn_mod_p(r, s)`，输入 `s` 为 8 个 64-bit 字）：

1. 取低 4 字 `s_lo = (s0, s1, s2, s3)`；
2. 取高 4 字 `s_hi = (s4, s5, s6, s7)`，按关系 `2^256 ≡ 2^224 + 2^96 − 2^64 + 1` 拆分为 4 个 ≤ 256-bit 的部分累加到 `s_lo`：
   - `s[4]·2^256  ≡  s[4]·2^224 + s[4]·2^96 − s[4]·2^64 + s[4]`（4 项 ≤ 256-bit）
   - `s[5]·2^320  ≡  s[5]·2^288 + s[5]·2^160 − s[5]·2^128 + s[5]·2^64`
   - `s[6]·2^384  ≡  s[6]·2^352 + s[6]·2^224 − s[6]·2^192 + s[6]·2^128`
   - `s[7]·2^448  ≡  s[7]·2^416 + s[7]·2^288 − s[7]·2^256 + s[7]·2^192`
     再把出现的 `2^256`、`2^288`、`2^352`、`2^416` 各自递归一次（每递归一次最高位下降 32-bit，三次后所有项均 ≤ 2^256）；
3. 把累加结果 mod `p`：由于展开后各项累加（每递归一层就把一个高位项拆成多个 ≤ 256-bit 项，递归 3 层后项数可达数十甚至上百，每项 ≤ 2^256），最终上界远大于 2·2^256，**不能只做 2 次减法**。正确做法是**循环条件减 `p`**（`while r >= p { r -= p }`），直到 `r < p`。这一步务必用 M1 的「随机 512-bit 输入与 `math/big` 模 p 比对 1000+ 组」兜底验证，不要硬编码减法次数。

**P3 备选公式**（仅供有 SM2 经验者参考；以 NIST P-256 汇编路径为模板、把符号翻转）：

```
T[0] = s0 + s4 + s5 − s6 − s7     (mod 2^64)
T[1] = s1 − s4 + s5 + s6 − s7     (mod 2^64)
T[2] = s2 − s5 + s6 + s7 − s4     (mod 2^64)
T[3] = s3 − s4 + s5 + s6 + s7     (mod 2^64)
T[0] += T[3] >> 63;  T[3] &= 0x7FFFFFFFFFFFFFFF
T[1] += T[0] >> 63;  T[0] &= 0x7FFFFFFFFFFFFFFF
... (条件减 p 三次)
```

> **TBV**：上述 P3 公式是符号调整后的草案，未经验证。实现期必须以「对随机 512-bit 输入与 `math/big` 模 p 结果比对 1000+ 组」为单位测试覆盖；任一组失败即回退 P2。

#### 2.1.2 模 `n` 约简

阶 `n` = `FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123` < 2^256。除「与 NIST P-256 等价关系式不同」外，**n 本身的二进制结构与 P-256 的 n 也完全不同**（P-256 n = `FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551`）。

实现方案：直接套用 `bn_sub` 做 2–3 次条件减：

```
// 输入：8 字 a，按大端（[low..high]）摆放
// 步骤 1：把 a 高 4 字按 n 的 256-bit 索引截断为 256-bit 不变量（n < 2^256）
// 步骤 2：连续 3 次 "if (a >= n) a -= n"
```

无快速路径可用。**禁止**尝试把 NIST P-256 的 `bn_mod_n` 套到 SM2 上。

### 2.2 层 1.5：曲线与点

- 类型 `SM2Point`（Jacobian 投影）= `(X, Y, Z)` 各为 `FixedArray[UInt64]`，长度 4；
- `affine` = `(x, y)` 同样 `FixedArray[UInt64]`；
- `point_infinity()` / `point_set_infinity(p)`：X、Y、Z 全零标记；
- `point_double(p)`、`point_add(p, q)`、`point_add_affine(p, q)`（q.z = 1 的快速加）；
- `point_to_affine(p) -> (x, y)`：先求 `Z^-1 mod p` 再乘；
- `point_is_on_curve(p)`：仿射版 `y^2 == x^3 + a*x + b (mod p)`；
- `point_eq(p, q)`：仿射比较；
- `scalar_mult(k, p)`：256-bit `k`，从最高位往左做 double-and-add；首版不引入 wNAF / 预计算表（gmsm 的预计算表 `sm2P256Precomputed` 是性能优化，正确性可由 scalar mult 通用路径覆盖；只有 `ScalarBaseMult` 走快速表是性能差异，不影响互操作）；
- `scalar_base_mult(k)`：直接调 `scalar_mult(k, G)`（后续替换为带预计算表版本）；
- `point_neg(p)`：`(x, -y mod p, z)`。

### 2.3 层 3：SM2 辅助函数

放在 `primitives.mbt`：

- `default_uid() -> Bytes` = `b"1234567812345678"`（与 gmsm 一致）；
- `za(curve, pub, uid) -> Bytes`：`H256(ENTL ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA)`；`ENTL` = `uint16(8 * uid.length())` 大端 2 字节（与 gmsm `sm2.go:449-451` 一致）；
- `msg_hash(za, msg) -> FixedArray[UInt64]`：`SM3(za ‖ msg)` 转 256-bit 整数；
- `kdf(length, parts...) -> Bytes`：循环 `(length+31)/32` 次 `SM3(parts ‖ ct)` 拼出 `length` 字节；若全 0 则返回 `ok=false`（与 gmsm 同）；`ct` 计数器为 `uint32` 从 1 起；
- `ke_x_hat(x) -> FixedArray[UInt64]`：等价于 `(x & ((1<<128) - 1)) | (1 << 127)`。
  - 步骤 1：清零 x 的高 128 bit（保留低 128 bit）；
  - 步骤 2：把低 128 bit 的最高位（bit 127）置 1，等价于「清零后再加 `2^127`」。
  - 注：gmsm 实现见 `gmsm/sm2/sm2.go:561-576`；其等价于 `bytes[hi-16] &= 0x7f`，然后 `r += 2^127`。
- `int_to_bytes_be(n : Int) -> Bytes`：`uint32` → 4 字节大端（KDF 计数器使用）。`n` 必须 ≥ 0 且 < 2^32，否则抛 `InvalidParameter`；gmsm 实现见 `gmsm/sm2/sm2.go:588-593`。

### 2.4 层 4：高层 API

`sm2.mbt` 暴露（与现有 `pkg.generated.mbti` 兼容，扩展方法为新签名）：

公开类型：

```mbt
// 256-bit 大数：小端 4 字 [low..high]
pub type Bn = FixedArray[UInt64]  // length 4

// 仿射点
pub struct SM2Point {
  curve : SM2Curve
  x : Bn
  y : Bn
}

// 公钥（不可变、带曲线引用）
pub struct SM2PublicKey {
  curve : SM2Curve
  x : Bn
  y : Bn
}

// 私钥（不可变、为大端 32 字节；公钥可由 derive_public_key 派生）
pub struct SM2PrivateKey {
  curve : SM2Curve
  d : Bn
  // 派生时填，否则按需重算
  mut public : SM2PublicKey?
}

// 曲线（常量、不可变）
pub struct SM2Curve {
  p : Bn
  a : Bn
  b : Bn
  n : Bn
  gx : Bn
  gy : Bn
}

// 密文布局
pub enum CipherMode {
  C1C3C2
  C1C2C3
}
```

> **设计说明**：
> - `SM2PublicKey` 同时存储 `curve` 引用，避免每个函数都额外传 `SM2Curve` 参数；
> - `Bn` 用 `FixedArray[UInt64]`（4 字）作为内部表示；对外 `Bytes` 走大端 32 字节；
> - `SM2PrivateKey` 与 `SM2PublicKey` 公开类型不可被调用方直接构造（首版用工厂函数 `generate_key` / `private_key_from_bytes` / `public_key_from_xy`）。

```mbt
// 曲线
pub fn sm2_p256() -> SM2Curve

// 密钥对
pub fn generate_key(random : @random.Rand?) -> SM2PrivateKey raise Sm2Error
pub fn derive_public_key(private_key : SM2PrivateKey) -> SM2PublicKey raise Sm2Error
pub fn private_key_from_bytes(curve : SM2Curve, d : Bytes) -> SM2PrivateKey raise Sm2Error
pub fn public_key_from_xy(curve : SM2Curve, x : Bytes, y : Bytes) -> SM2PublicKey raise Sm2Error

// 校验
pub fn is_on_curve(public_key : SM2PublicKey) -> Bool

// 签名（内部 r, s）
pub fn sm2_sign(
  private_key : SM2PrivateKey,
  msg : Bytes,
  uid : Bytes,
  random : @random.Rand?,
) -> (Bytes, Bytes) raise Sm2Error

pub fn sm2_verify(
  public_key : SM2PublicKey,
  msg : Bytes,
  uid : Bytes,
  r : Bytes,
  s : Bytes,
) -> Bool

// 签名（ASN.1 DER 形式）
pub fn sm2_sign_der(...) -> Bytes raise Sm2Error
pub fn sm2_verify_der(...) -> Bool

// 加解密（明文模式 C1C3C2 / C1C2C3）
pub fn sm2_encrypt(
  public_key : SM2PublicKey,
  msg : Bytes,
  random : @random.Rand?,
  mode : CipherMode,
) -> Bytes raise Sm2Error

pub fn sm2_decrypt(
  private_key : SM2PrivateKey,
  cipher : Bytes,
  mode : CipherMode,
) -> Bytes raise Sm2Error

// 加解密（ASN.1）
pub fn sm2_encrypt_asn1(...) -> Bytes raise Sm2Error
pub fn sm2_decrypt_asn1(...) -> Bytes raise Sm2Error
pub fn cipher_marshal(cipher : Bytes) -> Bytes raise Sm2Error
pub fn cipher_unmarshal(der : Bytes) -> Bytes raise Sm2Error

// 密钥协商
pub fn key_exchange_a(
  klen : Int, ida : Bytes, idb : Bytes,
  priA : SM2PrivateKey, pubB : SM2PublicKey,
  rpriA : SM2PrivateKey, rpubB : SM2PublicKey,
) -> (Bytes, Bytes, Bytes) raise Sm2Error
pub fn key_exchange_b(
  klen : Int, ida : Bytes, idb : Bytes,
  priB : SM2PrivateKey, pubA : SM2PublicKey,
  rpriB : SM2PrivateKey, rpubA : SM2PublicKey,
) -> (Bytes, Bytes, Bytes) raise Sm2Error

// 压缩
pub fn compress_point(p : SM2PublicKey) -> Bytes
pub fn decompress_point(b : Bytes) -> SM2PublicKey raise Sm2Error
```

> **算法要点（SM2 签名 / 验证，须与 gmsm `Sm2Sign`/`Sm2Verify` 对齐）**：
> - 记 `e = SM3(ZA ‖ msg)`，`ZA = SM3(ENTLA ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA)`；
> - 签名：`(x1, y1) = k·G`，`r = (e + x1) mod n`；若 `r = 0` 或 `r + k = n` 则换 `k` 重算；`s = (1+d)⁻¹ · (k − r·d) mod n`，若 `s = 0` 则换 `k` 重算（`k` 范围 `[1, n-1]`，见 §2.1）；
> - 验证：先拒 `r,s ∉ [1, n-1]` 或 `t = (r + s) mod n = 0`；否则 `(x1, y1) = s·G + t·P`，`R = (e + x1) mod n`，成功当且仅当 `R = r`。

> **命名约定**：与 gmsm TestKEB2 的返回值保持一致 —— `key_exchange_a` 返回 `(k, S1, S2)`、`key_exchange_b` 返回 `(k, S1, S2)`。GM/T 0003 协议中「B 侧计算的『B 侧的 S1』」即 gmsm 测试里的 `Sb`，「A 侧计算的『A 侧的 S2』」即 gmsm 测试里的 `Sa`；互验即 `key_exchange_a().1 == key_exchange_b().1` 且 `key_exchange_a().2 == key_exchange_b().2`（即 `S1 == Sb`、`S2 == Sa`）。

错误类型：

```mbt
pub suberror Sm2Error {
  ZeroParam             // 私钥 d = 0 或 d ≥ n
  NotOnCurve            // 点不在曲线 / 不在曲线 & Z∞
  InvalidCipher         // 密文 C3 校验失败 / 长度错误 / ASN.1 解码失败
  InvalidSignature      // 签名 ASN.1 解析失败
  InvalidPoint          // 压缩点首字节非法 / 椭圆曲线点无效
  InvalidParameter      // 通用参数错误（uid 过长、int_to_bytes_be 越界）
  ZeroRandom            // 随机源读取失败
  KdfZeroKey            // KDF 输出全 0
} derive(Show, Eq)
```

> 与 gmsm 的 `errZeroParam`（sm2.go:65）保持兼容；`InvalidParameter`/`InvalidSignature`/`InvalidPoint`/`KdfZeroKey` 是在 gmsm 错误语义上做的细化（gmsm 全部用 `errors.New("...")`，未细分）。

`@random.Rand?` 是 MoonBit 标准库的伪随机源（`moonbitlang/core/random`），缺省时使用确定性随机源 `zeroReader{}` 跑 KAT，正式运行时使用 `Rand::chacha8(...)`。

## 3. 互操作性与字节序约定

| 元素 | 字节序 | 长度 | 说明 |
| --- | --- | --- | --- |
| `Bytes` 与 `FixedArray[UInt64]` 互转 | 大端（MSB first） | 32 B / 256 bit | 匹配 gmsm `big.Int.Bytes()` |
| 仿射点字节表示 | 04 ‖ X ‖ Y | 65 B（总 65） | 与 gmsm `Encrypt/Decrypt` 的密文首字节一致 |
| 压缩公钥 | 02/03 ‖ X | 33 B（总 33） | 高 1 位表示 `y` 奇偶 |
| 签名 ASN.1 | `SEQUENCE { r INTEGER, s INTEGER }` DER | 可变（典型 70–72 B） | 与 gmsm `SignDigitToSignData` 一致 |
| 密文 ASN.1 | `SEQUENCE { x INTEGER, y INTEGER, hash OCTET STRING, cipherText OCTET STRING }` | 可变 | 与 gmsm `CipherMarshal` 一致 |
| 密文布局 `C1C3C2` | 04 ‖ C1(64) ‖ C3(32) ‖ C2 | 97 + klen 字节 | |
| 密文布局 `C1C2C3` | 04 ‖ C1(64) ‖ C2 ‖ C3(32) | 97 + klen 字节 | |
| `bn_rand_k` 输出 | 大端 | 32 B（范围 `[1, n-1]`） | gmsm `randFieldElement` 行为 |

与 gmsm 的「字节级互操作」通过以下两条路径保证：

1. 用 gmsm 公开的曲线参数、KAT、ZA、密文布局、签名的 ASN.1 结构作为外部 oracle；
2. 本规范的字节序、内部表示与 gmsm 行为完全一致（key 范围 `[1, n-2]`，sign 拒绝 r/s 越界，verify 拒绝 t=0 等）。

## 4. 测试数据来源

所有 KAT 取自 `gmsm/sm2/sm2_test.go` 与 `gmsm/sm2/sm2.go`、`gmsm/sm2/p256.go` 中的硬编码常量；本规范不引入任何「自造」测试向量。

### 4.1 曲线参数（来自 `p256.go:67-81`）

```text
p = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
R = 7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002
```

> 注：上表中的 `R` 在 gmsm 源码（`p256.go:75`）里的真实名字是 `RInverse`，是 gmsm 那套 9×29-bit 优化字段运算内部的 Montgomery 逆元常数，**不是 SM2 标准曲线参数**，也**不用于本规范推荐的 P2（4×64-bit Barrett）路径**，实现时无需引入。

### 4.2 默认 UID（来自 `sm2.go:37`）

```text
default_uid = "1234567812345678"  // 16 bytes
```

### 4.3 密钥协商 KAT（来自 `sm2_test.go:103-171` 的 `TestKEB2`）

```text
ida = "1234567812345678"
idb = "1234567812345678"
da  = 81EB26E941BB5AF1 6DF116495F906952
      72AE2C6D3D6C4AE1 678418BE48230029
db  = 785129917D45A9EA 5437A59356B82338
      EAADDA6CEB199088 F14AE10DEFA229B5
ra  = D4DE15474DB74D06 491C440D305E0124
      00990F3E390C7E87 153C12DB2EA60BB3
rb  = 7E07124814B30948 9125EAED10111316
      4EBF0F3458C5BD88 335C1F9D596243D6
expk = 6C89347354DE2484 C60B4AB1FDE4C6E5  (klen=16)
```

期望：

- `key_exchange_b(16, ida, idb, priv(db), pub(da), priv(rb), pub(ra)).0 == expk`
- `key_exchange_a(16, ida, idb, priv(da), pub(db), priv(ra), pub(rb)).0 == expk`
- 双方 `S1 == Sb` 且 `Sa == S2`（即 `key_exchange_a().1 == key_exchange_b().1` 且 `key_exchange_a().2 == key_exchange_b().2`，参见 §2.4 命名约定）。

### 4.4 签名的确定性 KAT（私钥使用 §4.3 的 `da`，随机源使用 gmsm `zeroReader` `sm2.go:663-674`）

为支持「固定随机源 → 固定签名」的可重复测试，引入 gmsm 同款 `zeroReader{}`（`sm2.go:663-674`）：

```text
type ZeroReader {}
fn read(dst : FixedArray[Byte]) -> Int { ... }   // 全 0 返回 dst.length()
```

把 `zeroReader` 作为 `random` 参数注入 `sm2_sign` / `sm2_encrypt` 后，可得到确定性输出。

**M4 强制验收项**：实施 M4（签名）时，**必须先用 gmsm Go 实现在等条件（含 `zeroReader`、固定私钥、消息、uid）下生成 1 组 KAT**，并把结果贴入下表。占位格式（实施期替换）：

```text
# 生成命令（在 gmsm 仓库目录下）
go test -run TestSm2SignDeterministic -v

# 私钥 d_hex        ：= §4.3 的 da = 81EB26E941BB5AF16DF116495F90695272AE2C6D3D6C4AE1678418BE48230029
# 消息 msg_hex       ：
# uid_hex           ：31323334353637383132333435363738  ("1234567812345678")
# 随机源            ：zeroReader（32 字节全 0）
# 期望 r_hex        ：TBD_由 M4 实施期由 gmsm Go 实现生成
# 期望 s_hex        ：TBD_由 M4 实施期由 gmsm Go 实现生成
# 期望 sign_der_hex ：TBD_由 M4 实施期由 gmsm Go 实现生成
```

> **禁止在 M4 提交前自行编造 r/s 值** —— 任何「我手算的」「我猜的」r/s 都会导致 round-trip 测试看起来通过但实际跨实现不可互操作。

### 4.5 加密布局 KAT（来自 `sm2_test.go:48-58` 的 `TestSm2`）

```text
msg = "123456"  (hex: 313233343536)
uid = "1234567812345678"
d   = 来自 §4.3 的 da（与签名 KAT 同一固定私钥）
random = ZeroReader{}
mode = C1C3C2
```

期望（结构层）：

- `len(cipher) == 1 + 64 + 32 + len(msg) == 103`；
- `cipher[0] == 0x04`；
- 解密回原 `msg`；
- 解密失败（错误 MAC）时返回 `Sm2Error::InvalidCipher`。

**M5 强制验收项**：实施 M5（加解密）时，**必须先用 gmsm Go 实现在等条件下生成 1 组 KAT**：

```text
# 期望 cipher_hex (C1C3C2) ：TBD_由 M5 实施期由 gmsm Go 实现生成
# 期望 cipher_hex (C1C2C3) ：TBD_由 M5 实施期由 gmsm Go 实现生成
# 期望 cipher_asn1_hex    ：TBD_由 M5 实施期由 gmsm Go 实现生成
```

占位阶段允许的最低验证（不依赖外生成 KAT）：

- `len(cipher) == 1 + 64 + 32 + len(msg)`；
- `cipher[0] == 0x04`；
- `decrypt(cipher) == msg`；
- 翻转 C3 区段内任一字节（如 `cipher[80]`；C3 位于密文 `[65..96]`，中间约 80）后 `decrypt` 抛 `Sm2Error::InvalidCipher`。

## 5. 测试方案

测试分布在三个文件：

| 文件 | 范围 | 类型 |
| --- | --- | --- |
| `sm2/sm2_wbtest.mbt` | 白盒（包内）：bn、点、ZA、KDF、`ke_x_hat` 的逐函数测试 | assertion |
| `sm2/sm2_test.mbt` | 黑盒（公开 API）：密钥、签名、加解密、密钥协商 | assertion + KAT |
| `sm2/sm2_spec.mbt` | spec 驱动：占位声明 + 类型驱动测试 | declare only |

### 5.1 白盒单测

`sm2/sm2_wbtest.mbt`：

1. **大数**
   - `bn_from_bytes` / `bn_to_bytes` 与硬编码常量往返；
   - `bn_addmod_p`、`bn_submod_p`、`bn_modmul_p` 已知向量（例如 `p-1` × `2` ≡ `-2 mod p`）；
   - `bn_modinv_p`：`a · a^-1 ≡ 1 mod p`；
   - `bn_mod_n`：私钥 `d=n-1` 应规约为 `n-1`、私钥 `d=n` 应拒绝。
2. **点**
   - `point_double(G) == 2G` 与硬编码 `2G` 比对（gmsm `sm2P256Precomputed` 的第 0 行 4 项即 `1G, 2G, 3G, ...`；首版只需手算 `2G` KAT）；
   - `point_add(G, G) == point_double(G)`；
   - `point_to_affine(scalar_mult(d, G))` 与 `derive_public_key(d)` 互验；
   - `point_is_on_curve` 拒绝 `G + (p-1, 0)` 等；
   - 负点 `(x, -y)` 与 `n-1 · G` 应相等。
3. **SM3**（沿用现有 `sm3_abc` 等 KAT）。
4. **ZA / KDF / ke_x_hat**
   - `za(pub_da, default_uid)`（`pub_da = derive_public_key(da)`，da 见 §4.3）与「手工拼装 ENTLA=0x0080 ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA」的 SM3 摘要比对（xA/yA 为该公钥的仿射坐标，不是基点 G）；
   - `kdf` 仅在派生出的 `length` 字节**全部为 0**时才返回 `ok=false`（概率极低）；对任意常规/零输入都应返回 `ok=true`。测试应断言 `kdf(16, x2, y2)` 返回 `ok=true`，并另行验证「全 0 输出 → ok=false」的判定分支；
   - `ke_x_hat(0xFFFF...FF)`（256-bit 全 1）= `(x & (2^128-1)) | 2^127` = `0x7FFF...FFF`（32 个十六进制数字、首位 0x7F，即 `2^128 + 2^127 - 1` 的低 128 位），与 gmsm `keXHat`（`sm2.go:561-576`）一致。

### 5.2 黑盒集成测试

`sm2/sm2_test.mbt`（**新增**，不复用现有 `sm2_wbtest.mbt` 的「假实现」断言）：

1. **密钥对**：
   - `generate_key(zero_reader)` 返回 `SM2PrivateKey`，对应公钥 `is_on_curve` 为真；
   - `derive_public_key(d)` 与 `generate_key(d, ...)` 在固定 `random` 下产出相同公钥；
   - `private_key_from_bytes(curve, d=zero)` 抛 `Sm2Error::ZeroParam`；
   - `private_key_from_bytes(curve, d=n)` 抛 `Sm2Error::ZeroParam`；
   - `public_key_from_xy(curve, x, y)` 其中 `(x, y)` 不在曲线上 → `Sm2Error::NotOnCurve`。
2. **签名 round-trip**：
   - 用 `generate_key` 产生密钥；
   - 固定 `uid = b"1234567812345678"`；
   - `sm2_sign(priv, msg, uid, ZeroReader{})` 得 `(r, s)`；
   - 断言 `sm2_verify(pub, msg, uid, r, s) == true`；
   - 翻转 `r` 一位后断言 `verify == false`。
3. **签名 DER round-trip**：
   - `sm2_sign_der` 得 ASN.1；
   - `sm2_verify_der` 通过；
   - 翻转 ASN.1 中 r 的最后一字节后断言 `verify == false`。
4. **签名 KAT**：以本规范 §4.3 中 `da` 作为私钥（`private_key_from_bytes(curve, da)`），固定 `msg=b"message digest"`、`uid=default_uid`、`random=ZeroReader{}`，期望 `(r, s)` 的 16 进制值（数值由「在 gmsm Go 测试中用同样输入跑出后贴入」；占位字段名 `sign_kat_r.hex` / `sign_kat_s.hex`，见 §7）。
5. **加密 round-trip**：
   - `sm2_encrypt(pub, msg, ZeroReader{}, C1C3C2)` 长度 = 1+64+32+len(msg)；
   - `sm2_decrypt(priv, cipher, C1C3C2) == msg`；
   - C1C2C3 同上；
   - 翻转 C3 任一字节后 `sm2_decrypt` 抛 `Sm2Error::InvalidCipher`；
   - `msg = b""` 应正常加解密。
6. **加密 KAT**：
   - `da` 作私钥（§4.5）；
   - `msg = b"123456"`、`random = ZeroReader{}`、`mode = C1C3C2`；
   - 期望密文 hex 字符串（与签名的「贴入」机制相同，见 §4.5 强制验收项）。
7. **ASN.1 round-trip**：`cipher_marshal` ↔ `cipher_unmarshal` 互逆。
8. **密钥协商 KAT**（核心）：完整复刻 `TestKEB2`。
   - 输入：`ida, idb, da, db, ra, rb, klen=16`（§4.3）；
   - 期望：`k1 == k2 == expk`，`S1 == Sb`、`S2 == Sa`（即 `key_exchange_a().1 == key_exchange_b().1` 且 `key_exchange_a().2 == key_exchange_b().2`）；
   - 同时验证 `key_exchange_a` 失败场景：`pubB` 传一个非法点 → `Sm2Error::NotOnCurve`；
   - 同时验证 `key_exchange_a` 失败场景：`v = ∞` 时抛 `Sm2Error::NotOnCurve`（gmsm 行为）。
9. **压缩 / 解压**：
   - `compress_point(pub_da)`（`pub_da = derive_public_key(da)`，da 见 §4.3）长度 = 33，首字节 ∈ {02, 03}；
   - `decompress_point(compress_point(G))` 恢复的 `x, y` 满足 `is_on_curve`；
   - 末位翻转后 `decompress_point` 抛 `Sm2Error::InvalidPoint`。
10. **跨实现互操作（手工 / CI 可选）**：
    - 在 Go 端跑 `gmsm/sm2`，用同一私钥 + zeroReader 产出 `sign_kat_r` / `sign_kat_s` / `enc_kat_cipher`，作为 fixture 文件落到 `sm2/testdata/`（命名约定见 §7）；
    - MoonBit 测试读 fixture 验证一致。
    - 该路径不在本规范硬性要求中，但 `docs/spec/spec_001_SM2.md` 留出 fixture 文件命名约定（见 §7）。

### 5.3 Spec-driven 测试（可选）

如果采用 `moonbit-spec-test-development` 的工作流，建立 `sm2/sm2_spec.mbt`，把 `SM2Curve`、`SM2PublicKey`、`CipherMode`、所有公开函数都用 `declare` 形式占位声明；测试文件以 `@json.inspect` / `assert_eq` 形式覆盖签名成功 / 失败、加密成功 / 失败、协商成功 / 失败 4 类断言，调用未实现函数时通过「实现文件再单独存在」的方式保证 spec 与实现可同时类型检查。

> 是否启用这一文件由实现阶段决定；本规范保留为可选项。

### 5.4 错误路径覆盖矩阵

| 错误条件 | API | 期望错误 |
| --- | --- | --- |
| `r, s ∉ [1, n-1]` | `sm2_verify` | 返回 `false` |
| `t = r + s mod n == 0` | `sm2_verify` | 返回 `false` |
| 密文 C3 与本地重算不一致 | `sm2_decrypt` | `Sm2Error::InvalidCipher` |
| KDF 全 0 输出 | `sm2_decrypt` | `Sm2Error::KdfZeroKey` |
| `rpub` 不在曲线上 | `key_exchange_a/b` | `Sm2Error::NotOnCurve` |
| `v = ∞` | `key_exchange_a/b` | `Sm2Error::NotOnCurve`（沿用 gmsm 行为） |
| 压缩首字节 ≠ 02/03 | `decompress_point` | `Sm2Error::InvalidPoint` |
| 私钥 d = 0 | `derive_public_key` / `private_key_from_bytes` | `Sm2Error::ZeroParam` |
| 私钥 d ≥ n | `private_key_from_bytes` | `Sm2Error::ZeroParam`（gmsm 用 `errZeroParam`） |
| 公钥点不在曲线 | `public_key_from_xy` | `Sm2Error::NotOnCurve` |
| uid 长度 ≥ 8192 字节 | `za` | `Sm2Error::InvalidParameter`（沿用 gmsm `uidLen >= 8192` 字节校验，`sm2.go:446`） |
| uid 为空 | `sm2_sign` / `sm2_verify` | 允许，gmsm 默认走 `default_uid` 路径 |
| msg 为空 | `sm2_sign` / `sm2_encrypt` | 允许，应正常返回 |
| 密文长度 < 97 | `sm2_decrypt` | `Sm2Error::InvalidCipher` |
| 密文首字节 ≠ 0x04 | `sm2_decrypt` | `Sm2Error::InvalidCipher` |
| DER 解码失败 | `sm2_verify_der` / `cipher_unmarshal` | 返回 `false` / 抛 `Sm2Error::InvalidCipher` |
| `@random` 注入失败 | `sm2_sign` / `sm2_encrypt` | `Sm2Error::ZeroRandom` |

> 注：上表中「密文长度 < 97」与「密文首字节 ≠ 0x04」两条是**本实现新增的防御性校验**，gmsm `Decrypt`（`sm2.go:325-344`）本身不做这两项检查（直接 `data[1:]` 取子串，短输入会越界而非返回该错误）。保留它们不会影响与 gmsm 的互操作（gmsm 产出的密文首字节恒为 0x04、长度恒定），但实现时应清楚它们是规范层的加固，不是 gmsm 行为。

## 6. 实施路线

| 里程碑 | 文件 | 验收 |
| --- | --- | --- |
| M1 大数层 | `sm2/bn.mbt` | `moon check`、`bn_*` 全部白盒通过；含 1000+ 组随机 512-bit 输入与 `math/big` 模 p/模 n 比对 |
| M2 点运算 | `sm2/curve.mbt` | `point_double/add` 与硬编码 KAT 比对通过 |
| M2.5 辅助函数 | `sm2/primitives.mbt` | `default_uid` / `za` / `kdf` / `ke_x_hat` / `int_to_bytes_be` 白盒通过；`za` 与手工拼装 ENTLA=0x0080 ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA 的 SM3 摘要比对 |
| M3 密钥对 | `sm2/sm2.mbt` 替换 `generate_key`/`derive_public_key`/`is_on_curve` | (a) `private_key_from_bytes(d)` 当 `d ∈ [0, n-1]` 时成功，`d == 0` 或 `d >= n` 时抛 `ZeroParam`；(b) 固定 `zeroReader` 作 `random` 时 `generate_key` 产出稳定公钥；(c) `derive_public_key(d)` 与 gmsm `ScalarBaseMult(d)` 在固定 d 下字节级一致 |
| M4 签名 | `sm2/sm2.mbt` `sm2_sign`/`sm2_verify` | 黑盒 round-trip + gmsm 生成的确定性 KAT 字节级一致（见 §4.4 强制验收项） |
| M5 加解密 | `sm2/sm2.mbt` `sm2_encrypt`/`sm2_decrypt` | 黑盒 round-trip + gmsm 生成的确定性 KAT 字节级一致（见 §4.5 强制验收项） |
| M6 协商 | `sm2/sm2.mbt` `key_exchange_a/b` | `TestKEB2` KAT 全通过（`k1 == k2 == expk`, `S1 == Sb`, `Sa == S2`） |
| M7 ASN.1 + 压缩 | `sm2/sm2.mbt` | DER round-trip + 压缩 round-trip + 错误路径覆盖矩阵（§5.4）全部通过 |
| M8 互操作（可选） | `sm2/testdata/*.txt` | 与 gmsm fixture 字节级一致 |

## 7. 测试数据文件约定

`sm2/testdata/`（白名单，提交到仓库）：

```text
sm2/testdata/
├── ke_b2.hex           # TestKEB2 全部 16 进制数据（§4.3）
├── sign_kat_da.hex     # 固定私钥 da
├── sign_kat_msg.hex    # 固定消息
├── sign_kat_r.hex      # 期望 r（由 gmsm CI 抓取）
├── sign_kat_s.hex      # 期望 s
├── enc_kat_cipher.hex  # 期望密文（C1C3C2）
└── zeroreader.bin      # 32 字节全 0
```

每个文件都是纯 16 进制 / 纯字节，测试代码用 `Bytes::from_array(hex_to_bytes(...))` 读入。fixture 内容由 gmsm 端首先生成并以 PR 形式提交，本规范不预先编造数值（避免「自证」）。

## 8. 风险与开放问题

1. **UInt64 性能**：4×64-bit 路径在 MoonBit 后端（wasm-gc / native / js）下未做过 benchmark。预期差异：
   - **native 后端**：与 gmsm Go 实现差距约 2–3×（gmsm 9×29-bit 字 + 预计算表 + wNAF，MoonBit 4×64-bit 通用路径）；
   - **wasm-gc 后端**：经 JS BigInt 中转，`bn_mul` 类操作再放大 10×+；
   - **js 后端**：不可用（`UInt64` 不支持）。
   - 缓解：M1 验收项增加 micro-benchmark（`moon bench` 在双后端跑 1000 次 sign/verify），如 wasm-gc 路径 < 50 ops/s，可考虑把 KAT 路径切到 native 或推迟 wasm-gc 支持。
2. **随机源注入**：`@random.Rand` 的 API 在不同 MoonBit 版本间可能调整；用「接口 + 缺省 zeroReader」的方式隔离 ABI 风险。
3. **ASN.1 解码**：MoonBit 暂无标准 ASN.1 库；首版手写 DER 解析（仅 2 个固定结构：`SEQUENCE { INTEGER, INTEGER }` 与 `SEQUENCE { INTEGER, INTEGER, OCTET STRING, OCTET STRING }`），后续可抽到独立包。
4. **互操作 fixture**：若 gmsm Go 测试不可在 CI 中运行，KAT 需在初始化实现时一次性离线生成并提交（见 §4.4、§4.5 强制验收项）。
5. **跨语言后端一致性**：M4 / M5 验收里要求固定的 `random` + `msg` 必须产生与 gmsm Go 一致的 `(r, s)` / `cipher`；如果 wasm-gc 后端的 `bn_mul` 中出现 64-bit 路径差异（例如溢出检查在 native/`+` 上溢 vs js 数值精度），需要单独记录一组跨后端 KAT 矩阵。

## 9. 验收清单

- [ ] M1–M7 全部 milestone 通过 `moon check` / `moon test`；
- [ ] `TestKEB2` 在本包以 KAT 形式通过；
- [ ] `sm2_decrypt` 在篡改 C3 后抛 `Sm2Error::InvalidCipher`；
- [ ] `sm2_verify` 在翻转 r/s 后返回 `false`；
- [ ] `sm2/testdata/` 中 fixture 全部到位并通过；
- [ ] `moon info` 与 `moon fmt` 无 diff。
