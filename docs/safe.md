## 安全审查结果

> **修复进度（2026-11-13，第二轮）**：本文所有 🔴 / 🟠 / 🟡 项均已落地，状态标注在各小节。
> 追加修复的内容见文末「第二轮修复记录」，那里同时修掉了本文未覆盖的
> DER 可延展性、PEM header 吞噬、`hex_to_bytes` 的 abort 面等问题。

我通读了 `sm2/`、`sm3/`、`sm4/`、`byteutil/`、`cmd/` 下的全部源码，并实际运行测试验证了其中两个问题。原生算法本身逐字节对照了 gmsm，没有发现差分或计时泄露之外的数学错误。问题集中在**默认随机源**、**不可信输入导致的崩溃**、**认证加密默认不安全**和**DER 解析边界检查不足**这四类。

---

### 🔴 严重（Critical）

> **状态：已修复。** 已删除 `sm2`、`sm4` 中的包级 `fallback_rand`；`generate_key` / `sm2_sign` / `sm2_sign_der` / `sm2_encrypt*` / `write_key_to_pem`（加密路径）在收到 `None` 时抛出 `MissingRandomSource`，不再静默使用固定种子；`sm2_sign` 之前忽略传入的随机源（内部写死 `bn_rand_k(None)`）也已修正。新增 `@sm2.os_rand()` / `@sm4.os_rand()`，用 `@env.rand` 的 OS 熵源播种；README 与 cmd 示例、测试均已改用该入口，并新增回归测试。

#### 1. 默认随机源是确定性伪随机，且暴露给调用方

涉及以下位置：
- [sm2/bn.mbt:628](sm2/bn.mbt#L628) `fallback_rand : @random.Rand = @random.Rand::chacha8()`
- [sm4/utils.mbt:94](sm4/utils.mbt#L94) 同样的写法
- [README.mbt.md:141](README.mbt.md#L141) 等所有示例都传 `None`

`chacha8()` 使用固定默认种子。`bn_rand_k(None)` 得到的签名随机数 `k`、`generate_key(None)` 得到的私钥 `d`、`sm2_encrypt(..., None, ...)` 得到的临时密钥，全部来自同一条公开可知的确定性序列。任何按 README 示例使用的代码都面临以下问题：

- 私钥可预测
- SM2 签名可恢复私钥（同一条 `k` 流 + 已知公钥即可算出 `d`）
- SM2 加密可解密

注释里"至少每次不同"的说法不足以解决问题；示例代码恰恰引导用户传 `None`。

**建议**：去掉 `None => fallback_rand` 兜底，让 `random` 成为必填参数；或在各平台接入 OS CSPRNG（如 `moonbitlang/x/sys` 的随机源）作为默认，并在文档中显著警告。

---

### 🟠 高（High）

> **状态：已修复。** `sm4_gcm_decrypt` 改签名并强制校验：`sm4_gcm_decrypt(key, iv, ct, aad, tag) -> Bytes raise`，内部用新增的 `@byteutil.ct_eq`（常量时间）比较 tag，不符（或 tag 非 16 字节）抛 `SM4Error::InvalidTag`，明文只在校验通过后返回。原不校验的 `(平文, tag)` 版本已删除，不再是公开 API。`sm4_gcm(..., encrypt=false)` 要求输入为 `密文‖tag`，必校验后才返回明文，长度不足 16 字节（无法携带 tag）直接拒绝。README 示例已改用新签名。

#### 2. `sm4_gcm` 解密后不校验 tag，且缺少 AEAD 解接口的默认语义

- [sm4/cipher.mbt:187-204](sm4/cipher.mbt#L187-L204)：`encrypt=false` 时直接返回 `(明文, tag)`，明文在认证之前就已产出。
- [sm4/sm4.mbt:668-712](sm4/sm4.mbt#L668-L712) 同样不校验。

调用方一旦忘记比较 tag（这是常见疏忽），就会被完全绕过认证，产生选择密文攻击。README 示例只用 `bytes_eq(tag, tag2)`，而 `bytes_eq` 也是提前返回的**非常量时间**比较（[byteutil.mbt:93](byteutil/byteutil.mbt#L93)）。

**建议**（已按此实施）：提供 `sm4_gcm_decrypt(key, iv, ct, aad, tag) -> Bytes raise`，内部用常量时间比较，tag 不符直接抛错；同时增加常量时间比较函数 `ct_eq`。

#### 3. DER 解析遇到不可信输入会崩溃（panic / abort），非攻击者可控范围之外几乎必然触发

已通过临时测试实测复现：

| 入口 | 输入 | 结果 |
|---|---|---|
| `sign_data_to_sign_digit` | 截断的 DER `30 10 02 01 00` | `RuntimeError: unreachable`（越界访问） |
| `sign_data_to_sign_digit` | INTEGER 内容 40 字节 | `abort("integer too large")` |
| `cipher_unmarshal` | 任意截断/伪造 DER | `RuntimeError: unreachable` |
| `sm2_verify_der` | 截断 DER | 依赖 `asn1_decode_signature`，同样会崩 |

根因：
- [sm2/sm2.mbt:437-462](sm2/sm2.mbt#L437-L462) `asn1_decode_signature` 与 [sm2/sm2.mbt:674-729](sm2/sm2.mbt#L674-L729) `cipher_unmarshal` 在每次 `der[off]`、`der[off:off+len]` 之前都没有边界检查。
- [byteutil/asn1.mbt:66-80](byteutil/asn1.mbt#L66-L80) `normalize_32` 用 `abort` 处理超长整数。
- [byteutil/asn1.mbt:47-64](byteutil/asn1.mbt#L47-L64) `decode_asn1_length` 对大长度的 `len << 8` 可能溢出成负数，随后被当作切片长度。

SM2 签名和密文通常来自网络或文件（例如加载签名之后才校验），因此远程即可造成 DoS。现有测试只覆盖"短到不足 4 字节"的输入（[sm2_test.mbt:168](sm2/sm2_test.mbt#L168)），没有覆盖"长度够但内容被篡改"。

**建议**：把 `cipher_unmarshal` 改为返回 `Result`/`raise Sm2Error`；解析器统一用"剩余长度检查"辅助函数，所有 `abort` 改为结构化错误；`decode_asn1_length` 增加长度上限与溢出检查。

#### 4. PEM 密钥加密（`write_key_to_pem` / `read_key_from_pem`）可被暴力破解

[sm4/aes.mbt:317-329](sm4/aes.mbt#L317-L329) `pem_legacy_key` 的密钥派生就是把口令**零填充**到 32 字节（RFC 1423 / 旧 `x509.EncryptPEMBlock` 方式），没有盐，也没有迭代。

任何拿到 PEM 文件的人都能以极低成本字典攻击恢复 SM4 密钥。这虽然是为了兼容 gmsm，但库对外暴露的接口不应该默认提供这种弱格式。

**建议**：新增基于 PBKDF2-HMAC-SM3（或 scrypt）的加密 PEM 格式作为默认；保留旧格式仅作只读兼容，并在文档中标注"不安全"。

---

### 🟡 中（Medium）

#### 5. SM2 解密中的认证标签比较非常量时间

> **状态：已修复（2026-11-13）。** C3 改用 `@byteutil.ct_eq` 常量时间比较；
> 同时把「点不在曲线上」「KDF 全零」「C3 不匹配」三种失败统一抛
> `Sm2Error::InvalidCipher`，错误码不再构成判定 oracle。

[sm2/sm2.mbt:624-628](sm2/sm2.mbt#L624-L628) 逐字节比较，首个不匹配即返回，存在通过计时侧信道推断 C3 的理论风险。改为常量时间比较即可。

#### 6. SM4 各模式使用包级共享默认 IV

> **状态：已标注废弃（2026-11-13）。** `set_iv` / `get_iv` 及依赖它们的
> `sm4_cbc` / `sm4_cfb` / `sm4_ofb` 全部加 `#deprecated`，文档指向显式 IV 的
> `sm4_encrypt_cbc` / `sm4_encrypt_cfb` / `sm4_encrypt_ofb`。为保持 gmsm 兼容没
> 有直接删除，但新代码或迁移代码不应再使用。

- [sm4/cipher.mbt:91](sm4/cipher.mbt#L91) `default_iv` 初始全零，`sm4_cbc/sm4_cfb/sm4_ofb(key, data, encrypt)` 不传 IV。
- `SM4Cipher` 里的 `iv` 字段与 `set_iv` 也只是设置初值，不自动随机化。

在 CBC 下重复 IV 会泄露相同明文前缀的相等关系；在 CFB/OFB 下重复使用 key+IV 是灾难性的（等价于流密码密钥重用）。零 IV 作为默认值没有任何提示，且包级可变全局状态存在并发数据竞争。

**建议**：让上层封装强制要求 IV，或每次加密随机生成并随密文返回；至少删掉包级可变 `set_iv`。

#### 7. 所有 `*_der` / `*_asn1` 接口对合法输入也可能返回错误类型

> **状态：已修复（2026-11-13）。** `normalize_32` 现在要求最小编码：
> `00 00 01`（冗余前导零）与 `00 80` 以外的多余零全部拒绝；长度字段的
> 长格式最小编码检查保留。签名 / 密文因此只有唯一合法字节表示。

`decode_asn1_length` 对长格式长度不检查"前导零 / 最小编码"，`normalize_32` 对 `INTEGER` 负数（首字节 ≥ 0x80 且无前导 0）也不拒绝，会静默包装或 abort。严格 DER 解析器应拒绝非最小编码与负数。

#### 8. GCM 实现偏离标准规范

> **状态：已修复（2026-11-13）。** `sm4_gcm_encrypt` / `sm4_gcm_decrypt` 改为
> **标准 GCM**：GHASH 长度块用比特长度、计数器 `gcm_inc` 按规范对末 32 位
> 模 2^32 自增。实测与 OpenSSL / Go `crypto/cipher` / Node `sm4-gcm` 输出一致。
> 原行为保留在 `sm4_gcm_encrypt_legacy` / `sm4_gcm_decrypt_legacy` 中，仅用于
> 与既有 gmsm 部署互通，两套结果互不兼容。

[sm4/sm4.mbt:539-554](sm4/sm4.mbt#L539-L554) 的 length 块使用**字节数**而非规范要求的**比特数**；[sm4/sm4.mbt:585-609](sm4/sm4.mbt#L585-L609) `gcm_inc` 在 `0xff+carry` 时回绕为 `0x00` 并吞掉进位。这些都为了对齐 tjfoc/gmsm 的缺陷，导致**与其他标准实现互不兼容**。如果有跨实现需求，会被误认为"加密结果正确但对方解不开"。

**建议**：在文档中醒目写明"与标准 GCM 不兼容"，或提供标准实现开关。

---

### 🟢 低 / 信息（Low）

- **私钥在内存中永不清零**：`SM2PrivateKey.d`、`SM4Cipher.rk` 等全程以普通 `FixedArray` 保存，析构后残留。**已提供 `SM2PrivateKey::wipe()` / `SM4Cipher::wipe()` 显式清零接口**（MoonBit 仍无析构钩子，调用方需自行调用）。
- **错误信息区分度**：`sm2_decrypt` 对"点不在曲线"和"C3 不匹配"抛不同错误码，可被用于 Oracle 探测；**已统一为 `InvalidCipher`**。
- **解码长度没有上限**：`base64_decode`、PEM 解析对合法但超大的输入不设限，存在内存放大风险（1 字节输入膨胀有限，但多层嵌套 PEM 可放大）。
- **`hex_to_bytes` 非法输入直接 `abort`**（[hexutil.mbt:31-41](byteutil/hexutil.mbt#L31-L41)），CLI 或上层若处理外部输入也会崩。**已改为 `raise ByteUtilError::InvalidHex`**，另提供字面量专用的 `hex_to_bytes_unchecked`。
- **`cmd/sm2` 示例直接 `println` 私钥**（[cmd/sm2/main.mbt:12-20](cmd/sm2/main.mbt#L12-L20)），作为演示尚可，但不应鼓励复制到生产。**已加 `[demo only]` 标注与「用完调用 `wipe()`」提示，并在示例末尾演示清零**。
- **`sm2/curve.mbt` 中的 `fallback` 分支**：`scalar_mult` 在 `k` 为 0 或点是无穷远时没有显式处理（`bn_is_zero(kk)` 时 digits 为空，结果直接为无穷远），目前由上层 `bn_rand_k` 保证非零，但作为公开库缺少防御性检查。

---

---

## 第二轮修复记录（2026-11-13）

上一轮结论里「已修复」的项逐条复验过，但复验同时暴露出**这批问题属于同一类**：
「一段合法数据可以被重新编码成字节不同、语义相同的另一段，而解析器照单全收」。
本轮把这条线一次堵死，并顺带修掉了几个崩溃面。

### 🔴 → ✅ DER 可延展性（signature / ciphertext 可被重编码）

| 位置 | 原行为 | 现行为 |
| --- | --- | --- |
| `asn1_sequence_children`（[sm2/sm2.mbt](sm2/sm2.mbt)） | 只保证 `SEQUENCE` 内部自洽，尾部字节被静默忽略 | 顶层调用时要求 `seq_end == der.length()`，尾部残留抛 `InvalidSignature` / `InvalidCipher` |
| `normalize_32`（[byteutil/asn1.mbt](byteutil/asn1.mbt)） | 剥前导零 + 左补零，`00 00 01` 照收 | 要求最小编码：除「高位为 1 时的一个 `0x00`」外，任何前导零都拒绝 |

实测覆盖（新增测试）：

- `sm2_der_rejects_trailing_bytes`：合法签名 / 密文后追加 `DE AD BE EF` /
  `00 01 02 03`，`sign_data_to_sign_digit`、`sm2_verify_der`、`cipher_unmarshal`
  全部拒绝。
- `sm2_sign_der_rejects_non_minimal_integer`：`INTEGER 00 00 01` 被拒绝。

### 🟠 → ✅ 错误模型统一（不再有 abort 通道）

| 入口 | 原行为 | 现行为 |
| --- | --- | --- |
| `sm2_sign` / `sm2_verify` / `sm2_key_exchange_*` 的 `uid` 过长 | 内部 `za` 走 `abort(...)`，进程崩溃 | `za` 改 `raise InvalidParameter`，所有调用方都是 `raise Sm2Error` |
| `key_exchange_a` / `key_exchange_b` | 无 `raise`，KDF 全零时 `abort` | 签名改为 `raise Sm2Error`，KDF 全零抛 `KdfZeroKey` |
| `sm2_decrypt` | `NotOnCurve` / `KdfZeroKey` / `InvalidCipher` 三种错误可分 | 统一 `InvalidCipher`，C3 改用 `ct_eq` 常量时间比较 |
| `hex_to_bytes` | 非法字符 / 奇数长度 `abort` | `raise ByteUtilError::InvalidHex`（新增错误变体） |

### 🟠 → ✅ GCM 改为标准实现

见上文 🟠 §8。关键点：**默认入口现在是标准 GCM**，gmsm 兼容行为需要显式选择
`_legacy` 变体。两套 KAT 都保留在测试里（`sm4_gcm_kat` /
`sm4_gcm_kat_legacy_gmsm`），后者同时断言「标准入口拒绝 legacy tag」。

### 🟠 → ✅ PEM / base64 解析

| 位置 | 原行为 | 现行为 |
| --- | --- | --- |
| `parse_block_at`（[byteutil/pem.mbt](byteutil/pem.mbt)） | 靠「这一行有冒号」判定 header，正文行可能被吞掉且无需空行 | header 段必须以空行结束，否则抛 `InvalidBase64` |
| `base64_decode` | 长度非 4 的倍数一律报错（`YWJjZA` 被拒）；padding 位置只查了 `pad > 0` | 接受省略 padding（与 Go `StdEncoding` 读取端一致），但 padding 必须完整且位于末尾 |
| `pkcs7_unpad_key`（[sm4/utils.mbt](sm4/utils.mbt)） | `n == 0` 时先 `data[n-1]` 越界再判 `n != 0` | 先判长度再取尾字节 |
| `sm4_pem_min_iterations` | 只有上限 1000 万，读取端可接受任意小的迭代次数 | 下限 10 万，读写两端都校验 |

### 🟡 → ✅ 易用性 / 默认值

- `set_iv` / `get_iv` 及依赖包级 IV 的三个 `mode bool` 包装加 `#deprecated`，
  文档指向显式 IV 的入口。
- `sm4_gcm(..., encrypt)` 加 `#deprecated`（返回值一半是废值），推荐
  `sm4_gcm_encrypt` / `sm4_gcm_decrypt`。
- 新增 `SM2PrivateKey::wipe()` / `SM4Cipher::wipe()`，`cmd/sm2` 演示调用。
- 删除模板残留的 `cmd/main`。
- `.githooks/pre-commit` 从只跑 `moon check` 补齐为
  `moon fmt --check` + `moon check --deny-warn` + `moon test --deny-warn`。

### 仍未处理（记录在案）

- `os_rand()` 在 `wasm-gc` 上仍会退化为「时钟 + 计数器」播种
  （`seed_from_entropy`），调用方无法区分真 OS 熵。彻底修它需要在 API 上把
  「有熵」和「无熵」分开，属于破坏性改动，留待单独讨论。
- `sm4_pem_default_iterations = 600000` 在 `wasm-gc` 上的实际耗时仍未标定。
- `SM2Point` 仍是 `pub(all)`。
- 私钥 / 轮密钥还有若干临时 `Bytes` 中间量没有清零。
