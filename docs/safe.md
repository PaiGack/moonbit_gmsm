# 审查结论

我用探针包实际跑了代码，探针已删除。仓库恢复原状，只剩会话开始时就在的 `scratch/` 和 `tmp_probe/`：这两个目录是历史遗留的探测残留，会导致 `moon check` 失败（未使用导入报错 E0029），建议删掉。**迁移后基线为：`moon test` 349/349 通过。**

按严重程度排序，每条都附实测证据和位置。

## 🔴 严重

**1. 私钥从包外可读、可改，私钥外泄属于无声的泄露**
`SM2PrivateKey`/`SM2PublicKey`/`SM2Curve` 的字段都是 `Bn = FixedArray[UInt64]`，`pub struct` 只隐藏字段名，不隐藏字段内容。探针实测：
```
A1 pri.d[0] readable from outside = 15617447642381805591
A2 pri.d[0] mutated from outside ok
outside package mutated pubkey.x[0] = 0
outside package mutated curve.n[0] = 1
```
见 [sm2.mbt:5](sm2/sm2.mbt#L5)、[sm2.mbt:18-28](sm2/sm2.mbt#L18-L28)。外部代码只要拿到 `SM2PrivateKey` 就能直接读出 `d` 的每个 limb；常量曲线 `sm2_p256()` 每次返回新数组，改它只会影响攻击者自己，但公钥污染是真实可做的。`wipe()` 只能清自己持有的那份。
建议：改用 `pub struct` + 私有 `FixedArray`，对外只暴露 `to_bytes()` 这种拷贝接口。

**2. 外部可以凭空构造任意 `SM2Point`**
`SM2Point` 是 `pub(all)`（[curve.mbt:6](sm2/curve.mbt#L6)），探针实测外部能构造 `SM2Point::{x:[1,..]}`。`spec_003_idioms.md` 声称「公共 API 过度暴露已经解决」，但 `docs/safe.md` 末尾自己也承认「`SM2Point` 仍是 `pub(all)`」，两处文档互相矛盾。

**3. `wipe()` 之后 API 静默产生垃圾结果**
文档说「The key is unusable afterwards」，实际不会报错：
```
wipe then encrypt -> silently returned 8f8a24f6c1b69fd7df46c0fcf655cc3e
wiped key sign -> r=eef98a70...
wiped key derive -> pub.x all zero = true
```
`SM4Cipher::wipe` 同理。至少应在对象内加一个 `wiped` 标志，让后续操作用抛错拒绝。

**4. SM2 KDF 的复杂度是 O(n²)，大消息形同 DoS**
[primitives.mbt:91-101](sm2/primitives.mbt#L91-L101) 每 32 字节都 `concat_bytes(parts)` 一次，而 `parts` 是整段明文（最多 65 字节），所以总量是 O(n²)。实测（native release）：
```
encrypt 5MB ms=280161
decrypt 5MB ms=290515
```
作为对比：SM3 5MB 只要 37ms，AES 类 SM4-ECB 5MB 87ms，GCM 5MB 约 1s（GCM 那 1s 也偏高，`gf_mult_arr` 是位级实现）。而 SM2 本身只用来加密短消息，5MB 这种规模属于误用，但用起来不会有任何提示。修复方式是循环外只拼接一次前缀，循环内只拼计数块。

## 🟠 高

**5. `key_exchange_*` 不校验 `klen`**
```
klen=0  -> ok k.len=0（A/B 两边都"成功"，s1/s2 还相等，但共享密钥是空串）
klen=-5 -> RAISED KdfZeroKey  ← 参数错误被报成了"KDF 全零"
klen=200 -> ok
```
见 [sm2.mbt:790](sm2/sm2.mbt#L790)、[primitives.mbt:86](sm2/primitives.mbt#L86)。负数 klen 能走到 `kdf` 的 `length == 0` 分支以外，是因为 `length + 31` 的除法对负数也会返回正数；最后得到 `(b"", false)`，被误报为 `KdfZeroKey`。应改为 `raise InvalidParameter`。

**6. `sm2_decrypt` 不校验 C3 长度，允许截断 C2**
```
encrypt(empty) -> len=97
decrypt(truncated C2, 只留 97 字节) -> SUCCESS len=0
```
[sm2.mbt:645](sm2/sm2.mbt#L645) 只检查 `< 97`。C1C3C2 下 C2 为空、C3 校验自然对所有空消息一致，这让「截掉 C2 获得空明文」成为常见路径；C1C2C3 下也没校验 C3 是否恰好 32 字节。建议统一要求 `length >= 97 + 32` 一类明确下界（或按模式校验 C2/C3 各自长度）。

**7. SM4 GCM 接受任意长度（包括 0）的 nonce**
```
gcm with zero-length IV/nonce -> ok b"secret"
```
[sm4.mbt:682](sm4/sm4.mbt#L682) 未校验 `iv.length()`。零 nonce + 固定 key 即 `key/nonce` 复用，属于灾难性问题：GCM 下会泄露明文异或和 H 的认证密钥。建议拒绝空 nonce（非 96 位可以保留，只要不拒绝，但应至少文档提示）。

**8. `pem_encode` 不做头部值校验，可注入任意头部**
```
write pem with headers [("Proc-Type", "4,ENCRYPTED\nDEK-Info: AES-256-CBC,00")]  →
-----BEGIN SM4 KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,00
...
```
用 Python 独立实现的 base64 解码确认，这条注入会变成新的头部行且正常解码（`decoded: b'0123456789abcdef'`）。见 [pem.mbt:49-52](byteutil/pem.mbt#L49-L52)。`write_key_to_pem` 自己传的头部是常量，暂时无风险，但 `pem_encode` 是公开 API，调用方传入 user-controlled 值就会造成 PEM 头注入（把 `SM4 KEY` 伪装成加密块等）。

**9. 错误语义不一致，文档承诺有出入**
- `README.md:21` 说「所有对外入口都用 `raise Sm2Error` 报告失败，不会 abort/panic」；但 [sm2.mbt:318](sm2/sm2.mbt#L318) 的 `abort("unreachable")`、[hexutil.mbt:39](byteutil/hexutil.mbt#L39) 的 `hex_nibble` 仍在。前者理论上不可达，后者是 `pub` 函数且**直接 abort**（`hex_to_bytes` 已经绕开它，这个 `hex_nibble` 是死代码且危险）。
- `sm2_verify_der` 遇到畸形 DER 返回 `false`（[sm2.mbt:564](sm2/sm2.mbt#L564)）；`sm2_verify` 遇到长度或范围错误却抛 `InvalidSignature`。探针显示：
```
der[0..3] -> returned false
verify(31-byte r) -> RAISED InvalidSignature
```
同一个「验签失败」在不同入口有「返回 false」和「抛异常」两种形态，调用方必须写两种错误处理，而且 `false` 无法和「签名确实不匹配」区分。
- `docs/spec/spec_001_SM2.md` §5.4 说 `r,s ∉ [1,n-1]` 时 `sm2_verify`「返回 `false`」，但实现抛 `InvalidSignature`。

## 🟡 中

**10. base64 接受非规范尾位**
```
base64(YWJjZB) -> 61626364    // 末 2 位未清零仍照收
base64(YWJjZA) -> 61626364
```
[base64.mbt:148-160](byteutil/base64.mbt#L148-L160) 丢弃了末组未使用的低位。这不会导致解码错误，但破坏了「同一份数据只有唯一编码」的承诺，和本项目在 DER 上刻意做的严格化（拒绝冗余前导零）方向不一致。

**11. 公开发布的弱兼容入口仍在文档里被推荐**
`sm4_ecb` / `sm4_cbc` / `sm4_cfb` / `sm4_ofb`（[cipher.mbt:165-235](sm4/cipher.mbt#L165-L235)）**没有**加 `#deprecated`，而同时 `set_iv`/`get_iv` 加了。用默认零 IV 的 `sm4_cbc` 仍是 README 第 38 行推荐入口（README 只写了这 4 个封装），却没有任何 IV 必填的提示。`sm4_cbc` 用零 IV 时同一 key 前 16 字节总是相同的 XOR 后处理基数，实测两段不同前缀产生不同密文只是因为明文不同，但它确实每次都复用 IV。

**12. `docs/safe.md` 列为「已修复/已标注」的项与现状不符**
- 「已标注废弃 `sm4_cbc/cfb/ofb`」——实际没标。
- 「解码长度没有上限」——safe.md 归到「低/信息」，`pem_decode` 仍然对任意大输入无上限。
- 关于 `SM2Point`、`os_rand()` 在 wasm-gc 上退化的记录是对的，属于已知遗留。

**13. `sm2_sign` 的 `abort("unreachable")`** 在 `while true` 循环后，编译器无法证明不可达，一旦出现反常（例如随机源永远返回非法 k）就 abort 而不是报错。`bn_rand_k` 在 `None` 时抛错，但传进一个「坏的 Rand」时没有上界。

## 🟢 低 / 已验证无问题的部分

- **GCM 非 96 位 IV 实现正确**：我用 Python 独立实现交叉验证 `iv=000102...1011`（136 位）时 `ct=dab640868e tag=f158b2ab65c473d735ecb5aeed510e85`，与源码完全一致。
- **legacy PEM 与 OpenSSL 互通**：用 `openssl enc -d -aes-256-cbc` 成功解出 `0123456789abcdeffedcba9876543210`。
- **SM4 默认 PEM（PBKDF2 60 万次）**：实测约 **2.56 秒**，对交互式使用偏慢但属于可接受的安全代价，文档可标出耗时。
- **SM4 自检向量**、SM3 / SM4 大消息流式与一次性结果一致、SM2 签名约 9ms/次，都正常。
- `docs/gap_analysis.md` 功能差距清单与实现一致（A6 通用 ASN.1 确实未做）。

## 建议修复顺序

1. 私有化 `SM2PrivateKey`/`SM2PublicKey`/`SM2Curve`/`SM2Point` 内部数组（问题 1、2），这是破坏性 API 变更，越早越好。
2. 修 `klen` 校验、SM2 密文长度校验、GCM nonce 校验（问题 5、6、7），都是小改动。
3. 修 KDF O(n²)（问题 4），约 10 行。
4. 统一验签错误语义、`pem_encode` 头部校验、删除 `hex_nibble`（问题 8、9）。
5. `wipe()` 加保护标志（问题 3）。
