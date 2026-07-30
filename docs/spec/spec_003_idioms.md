## 一、架构层面：公共 API 过度暴露

**skill 依据**：`moonbit-refactoring` — "Minimize public API: remove `pub` from helpers; keep only required exports"

`sm2/pkg.generated.mbti` 暴露了 **40+ 个公开函数**，其中大量是内部实现细节，不应对外可见：

| 类别 | 不应 `pub` 的函数 | 说明 |
|------|-------------------|------|
| 大数运算 | `bn_is_zero`, `bn_zero`, `bn_copy`, `bn_from_bytes`, `bn_to_bytes`, `bn_eq`, `bn_lt`, `bn_gt`, `bn_add`, `bn_sub`, `bn_mul`, `bn_sqr`, `bn_mod_p`, `bn_modmul_p`, `bn_modsqr_p`, `bn_mod_n`, `bn_modinv_p`, `bn_exp_mod_p`, `bn_addmod_p`, `bn_submod_p`, `bn_rand_k` | 底层算术，调用方无需直接使用 |
| 点运算 | `point_infinity`, `point_is_infinity`, `point_set_infinity`, `point_copy`, `point_to_affine`, `point_add`, `point_add_affine`, `point_double`, `point_neg`, `point_eq`, `scalar_mult`, `scalar_base_mult` | 曲线运算内部细节 |
| 辅助 | `za`, `msg_hash`, `kdf`, `ke_x_hat`, `int_to_bytes_be`, `point_is_on_curve_affine` | 密码学原语内部步骤 |

相比之下，`sm3` 的 API 面很干净（仅 `new`/`sm3_sum`/`sm3_sum_multi` + 6 个方法），是好的范例。

**建议**：将这些降级为包内私有（去掉 `pub`），只保留 `sm2_sign`/`sm2_verify`/`sm2_encrypt`/`sm2_decrypt`/`generate_key`/`derive_public_key` 等高层 API。

---

## 二、编程范式：Go/C 风格而非 MoonBit 惯用法

### 2.1 Buffer 传递模式（最突出的风格问题）

**skill 依据**：`idioms.md` — "Prefer small direct code over abstractions"；`refactoring` — "Convert free functions to methods + chaining"

`bn.mbt` 和 `curve.mbt` 全面使用 Go 风格的"传出缓冲区作为第一个参数"：

```moonbit
// 当前写法（Go 风格）
pub fn bn_modmul_p(r, a, b) -> Unit { ... }
pub fn bn_add(r, a, b) -> UInt { ... }
pub fn point_add(p, q) -> Unit { ... }  // 就地修改 p

// MoonBit 惯用法：返回结果
fn bn_modmul_p(a, b) -> FixedArray[UInt64] { ... }
fn point_add(p, SM2Point, q : SM2Point) -> SM2Point { ... }
```

这导致调用点充斥大量样板：
```moonbit
// sm2.mbt:271-283 — 12 行只为做一次 (1+d)^-1 mod n
let one_plus_d : Bn = FixedArray::makei(4, fn(_) { 0UL })
let da8 : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { ... })
add_to_8(da8, private_key.d)
bn_mod_n(one_plus_d, da8)
let inv : Bn = FixedArray::makei(4, fn(_) { 0UL })
bn_modinv_n(inv, one_plus_d, n)
```

### 2.2 C 风格 `for` 循环

**skill 依据**：`refactoring` — "Prefer `for i in 0..<n` or `for x in xs`"

全代码库统一使用 C 风格循环，未使用 MoonBit 的区间迭代：
```moonbit
// 当前（遍布 sm2/sm3/sm4）
for i = 0; i < 4; i = i + 1 { ... }
for j = 0; j < len; j = j + 1 { ... }
for i = 0; i < 8; i = i + 1 { ... }

// MoonBit 惯用法
for i in 0..<4 { ... }
for _ in 0..<len { ... }
for i, x in xs { ... }
```

### 2.3 `while true` + `break`/`return`

**skill 依据**：`refactoring` — "Prefer functional loops to mutation when possible"

`generate_key`、`sm2_sign`、`bn_rand_k` 都用 `while true { ... break/continue/return }`：
```moonbit
while true {
  let buf = Bytes::makei(32, ...)
  bn_from_bytes(d, buf, 0)
  if !bn_is_zero(d) && bn_lt(d, curve.n) { break }
}
```

---

## 三、注释与块风格不统一

### 3.1 `///` 文档注释 vs `//` 普通注释混用

`bn.mbt` 中大量函数用 `//` 而非 `///` 做文档说明：
```moonbit
// bn.mbt:6   // SM2 prime p = ...        ← 应为 ///
// bn.mbt:20  // SM2 curve order n         ← 应为 ///
// bn.mbt:119 // Internal: read UInt64...  ← 应为 ///
// bn.mbt:132 // Multiply two UInt64...    ← 应为 ///
```

而 `sm3.mbt`、`sm4.mbt` 一致使用 `///`，风格不统一。

### 3.2 Go 风格的段落标记

```moonbit
// sm2.mbt:201  // --- helpers ---
// sm2.mbt:407  // --- ASN.1 DER ---
// sm2.mbt:631  // --- Encrypt/Decrypt ---
// sm2.mbt:861  // --- Key Exchange ---
// sm2.mbt:1031 // --- Compression ---
```

这不是 MoonBit 惯例。按 `AGENTS.md`，代码以 `///|` 分块，文件本身就是组织单元，不需要此类分隔标记。

### 3.3 `hexutil.mbt` 首行用了 `//|` 而非 `///`

```moonbit
//| Shared hex / byte helpers ...   ← hexutil.mbt:1
```

---

## 四、重复代码

### 4.1 跨包重复的工具函数

| 函数 | sm2 | sm3 | sm4 |
|------|-----|-----|-----|
| `rotl(UInt, Int)` | — | `sm3.mbt:206` | `sm4.mbt:74` |
| `get_u32_be` | — | `sm3.mbt:188` | `sm4.mbt:81` |
| `concat_bytes`/`concat_bytes_array` | `primitives.mbt:72` + `sm2.mbt:529` | — | — |

`rotl` 和 `get_u32_be` 在 sm3 和 sm4 中逐字重复。`concat_bytes` 在 sm2 包内就有两份不同实现（`primitives.mbt` 和 `sm2.mbt`）。

### 4.2 常量重复定义

SM2 素数 `p` 的 4 个 limb 值在以下位置逐字重复：
- `bn.mbt:7` (`p_limbs()`)
- `curve.mbt:91` (`point_is_on_curve_affine` 内联)
- `curve.mbt:386` (`point_neg` 内联)
- `sm2.mbt:56` (`sm2_p256()` 中 `p` 字段)

曲线参数 `a`、`b`、`gx`、`gy` 同样在 `sm2.mbt` 和 `primitives.mbt` 中各自重复定义。

### 4.3 sm4 内的块转换重复

`sm4.mbt` 已定义 `block_to_words`/`words_to_block` 辅助函数（`sm4.mbt:435-447`），但 `sm4_encrypt_ecb`、`sm4_decrypt_ecb`、`sm4_encrypt_cbc`、`sm4_decrypt_cbc` 内联重复了同样的转换逻辑，未复用已有函数。

---

## 五、冗余的类型标注

**skill 依据**：`idioms.md` — "Prefer small direct code"

MoonBit 有类型推断，但代码中大量冗余标注：
```moonbit
let s8 : FixedArray[UInt64] = FixedArray::makei(8, fn(_) { 0UL })  // 类型可推断
let one : Bn = FixedArray::makei(4, fn(i) { if i == 0 { 1UL } else { 0UL } })
let z : FixedArray[Byte] = FixedArray::makei(16, fn(_) { b'\x00' })
```

`sm2.mbt` 中 `sm2_sign` 函数体（约 80 行）几乎每个 `let` 都带显式类型标注，且伴随 `FixedArray::makei(4, fn(_) { 0UL })` 的零值初始化样板。

---

## 六、错误处理不一致

**skill 依据**：`idioms.md` — "Use MoonBit's typed error model when the surrounding code uses `raise`"

| 位置 | 当前方式 | 问题 |
|------|---------|------|
| `asn1_decode_signature` | 返回 `Result[(Bytes, Bytes), String]` | 用 String 而非已有错误类型 |
| `cipher_marshal` / `cipher_unmarshal` | `abort("invalid cipher")` | 应 `raise Sm2Error` |
| `normalize_32` | `abort("integer too large")` | 应 `raise` |
| `decode_asn1_length` | `abort("ASN.1: out of bounds")` | 应 `raise` |
| `sm2_sign` 中 KDF 失败 | 不可能发生但用 `abort("unreachable")` | 可接受 |
| `key_exchange_a/b` 中 KDF 失败 | `abort("KDF all-zero key")` | 应 `raise` |
| `hexutil.hex_nibble` | `abort("invalid hex char")` | 应 `raise` |

`asn1_decode_signature` 已正确返回 `Result`，但 `cipher_marshal`/`cipher_unmarshal` 对同样的 ASN.1 解析错误却用 `abort`，风格不统一。

---

## 七、`match` + `_ => abort("unreachable")` 样板

固定大小数组的初始化反复出现此模式（10+ 处）：
```moonbit
FixedArray::makei(4, fn(i) {
  match i {
    0 => 0xFFFFFFFFFFFFFFFFUL
    1 => 0xFFFFFFFF00000000UL
    2 => 0xFFFFFFFFFFFFFFFFUL
    3 => 0xFFFFFFFEFFFFFFFFUL
    _ => abort("unreachable")
  }
})
```

MoonBit 中可用数组字面量更简洁：
```moonbt
FixedArray::from_array([
  0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFF00000000UL,
  0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFEFFFFFFFFUL,
])
```
（需验证 `FixedArray::from_array` 是否可用，可运行 `moon ide doc '*FixedArray*'` 确认）

---

## 八、其他细节问题

| # | 位置 | 问题 |
|---|------|------|
| 1 | `sm2.mbt:882,948` | `let _curve = priA.curve` 赋值后未使用，应直接删除 |
| 2 | 多处 | `fn(_) { 0UL }` 与 `fn(_i) { 0U }` 混用，下划线参数命名不一致 |
| 3 | `sm3.mbt:189` | 用 `.land(0xffU)` 方法，而 `sm4.mbt:82` 用直接 `<< 24`（因 `to_uint()` 已保证 0-255），风格不一致 |
| 4 | `sm2.mbt:197,68` 等 | `sm2_error_zero_random()`、`cipher_mode_c1c2c3()` 等仅为"API 完整性"构造变体，实为兼容包装。按 `AGENTS.md` 应放入 `deprecated.mbt` |
| 5 | `sm4.mbt:163` | `let n = 4` 常量只用一次，可内联 |
| 6 | `sm4/cipher.mbt:91` | `default_iv` 是包级可变全局状态，不符合 MoonBit 函数式偏好 |
| 7 | `sm2` 类型 | `pub type Bn = FixedArray[UInt64]` 定义了别名，但代码中 `Bn` 和 `FixedArray[UInt64]` 混用，未统一 |

---

## 总结优先级

| 优先级 | 问题 | 影响范围 |
|--------|------|---------|
| **高** | 公共 API 过度暴露（§一） | `sm2` 整个包 |
| **高** | Buffer 传递 + 就地修改范式（§二.1） | `sm2/bn.mbt`、`curve.mbt` |
| **高** | 跨包重复函数（§四.1） | `sm3`+`sm4` |
| **中** | C 风格循环（§二.2） | 全部 |
| **中** | 注释风格不统一（§三） | `sm2/bn.mbt` 尤甚 |
| **中** | 常量重复定义（§四.2） | `sm2` 多文件 |
| **中** | 错误处理混用 abort/raise/Result（§六） | `sm2` 为主 |
| **低** | 冗余类型标注（§五） | 全部 |
| **低** | `match`+`abort` 样板（§七） | `sm2` |
| **低** | 细节问题（§八） | 零散 |

如需我按优先级开始修改，或对某个具体问题展开更详细的改法示例，请告知。