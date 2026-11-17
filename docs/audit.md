# 审查结论（2026-11-16）

本轮对 `sm2` / `sm3` / `sm4` / `byteutil` 的非测试代码做了一次全量审计，重点为
安全、边界、易用性，以及文档承诺与实现的一致性。基线：`moon test --deny-warn`
**349/349 通过**，`git status` 干净。

标 **【实测】** 的条目已在仓库副本中写探针跑过；标 **【读码】** 的结论来自代码
路径分析，未单独构造输入验证。

---

## 🔴 严重

### S1. `d = n-1` 的合法私钥签名时死循环【实测】【已修复】
[crypto 签名][sm2/sm2.mbt:293] 计算 `inv = (1 + d)⁻¹ mod n`。`d = n-1` 时
`1 + d ≡ 0`，`bn_modinv_n(0)` 返回 0，于是 `s = inv · t ≡ 0` 恒成立；
[sm2.mbt:343] 的 `if bn_is_zero(s) { continue }` **永不退出**，循环内重新取 k
也改变不了 `s`。

- 探针：`private_key_from_bytes(curve, n-1)` 被接受 → `sm2_sign` 输出
  `d=n-1 accepted …` 后整轮测试超时被杀。
- 影响：一个合法的 256-bit 私钥值（概率 2⁻²⁵⁶，但可由外部文件 / 测试向量 /
  攻击者提供的 PKCS#8 导入）即可让服务端签名请求挂死。
- 修法：`private_key_from_bytes` 与 `generate_key` 拒绝 `d == n-1`，或在
  `sm2_sign` 计算 `one_plus_d` 后为 0 时 `raise InvalidParameter`（两者都做更稳）。
  同时把 `while true` 改为有界重试 + 最终 `raise`，去掉 [sm2.mbt:348] 的
  `abort("unreachable")`（它违反 README「不 abort」的承诺）。

**修复状态（2026-11-16）**：上述三处均已落地——
`check_private_scalar` 拒绝 `d = n-1`（`InvalidParameter`），`generate_key`
在拒绝采样中跳过它；`sm2_sign` 在 `(1+d) mod n == 0` 时立即
`raise InvalidParameter`；`sm2_sign`、`bn_rand_k`、`generate_key` 的采样循环
统一为 64 次有界重试，超限 `raise MissingRandomSource`，`abort` 已删除。
白盒测试：`private_key_from_bytes_rejects_n_minus_1`、
`private_key_from_bytes_accepts_n_minus_2`、`degenerate_random_source_does_not_hang`。

### S2. `os_rand()` 在无熵平台上静默退化，`MissingRandomSource` 永远不会触发【读码】
[sm2/bn.mbt:652] `os_entropy()` 的 `None => Some(seed_from_entropy())` 使得
`os_rand()` **总是**返回 `Some`。`seed_from_entropy` 自己的文档
（[sm2/seed_entropy.mbt:14]）就写明：在完全隔离的 wasm-gc 主机上只剩
「时钟 + 调用计数器」，「not unpredictable」。

- 影响：`generate_key(os_rand())`、`sm2_sign(..., os_rand())` 在 wasm-gc
  沙箱里会用可预测的种子生成私钥与签名随机数 k——这是灾难性的。而
  README 宣称随机源「不可用即报错、无退化回退」。
- 探针：native 上无法区分两种来源，代码路径即可判定。
- 修法：`os_entropy()` 在 `@env.rand` 返回 `None` 时也返回 `None`；把
  `seed_from_entropy` 保留为显式的、文档标注不安全的接口。`sm4/utils.mbt:233`
  的 `os_rand` 同样处理。

**修复状态（2026-11-16）**：按「保留 wasm 可用性」的决定，处理方式是
**退化 + 告警**而不是报错——`sm2::os_entropy()` 在 `@env.rand` 为 `None` 时先向
stderr 打印 `[gmsm] WARNING: no OS entropy source available ...`，再退回
`seed_from_entropy()`；`sm4::os_rand` 同样处理（告警后调用
`@sm2.seed_from_entropy()`）。退化不再是静默的，`MissingRandomSource` 只保留给
调用方显式传入 `None` 的情形。`seed_from_entropy` 文档仍标注「not
unpredictable」。README 新增「随机源」段落说明该行为。测试 352/352 通过。

### S3. 密钥协商不校验任何公钥/临时点的曲线成员关系，静默算出错误密钥【实测】【已修复】
[sm2.mbt:853-857]（A 侧）与 [sm2.mbt:916-920]（B 侧）把 `rpubB` / `pubB`
直接喂给 `point_from_pubkey` + `scalar_mult`，**没有** `point_is_on_curve_affine`。
相比之下 `sm2_decrypt` 对 C1 是校验的（[sm2.mbt:689]）。

- 探针：把对方公钥的 y 翻转（不在曲线上）后调用 `key_exchange_a`，**不报错**，
  协商出 `k=9cc477…`；诚实 B 侧得到 `k=ad747d…`，两边不一致——错误被推迟到
  业务层才发现，密钥确认 S1/S2 所依赖的输入已不可信。
- 修法：两个入口开头对静态与临时公钥做曲线检查，失败 `raise NotOnCurve`；
  并校验双方 `curve` 参数一致（目前 `SM2Curve` 由调用方传入且可被改写，见 M2）。
- 补充：现有测试 `sm2_key_exchange_rejects_off_curve_peer`
  （[sm2/sm2_test.mbt:406]）实际只覆盖了「B 侧 `pubB` 不在曲线上」这一条，
  临时点与 A 侧都没有覆盖，测试名有误导。

**修复状态（2026-11-17）**：`key_exchange_a` / `key_exchange_b` 入口现在先做
两层检查，再进入任何标量乘法——

- `same_curve`：四把密钥的 `p / a / b / n / gx / gy` 六项必须与
  `sm2_p256()` 完全一致，否则 `raise InvalidParameter`。`b` 必须比较：只在
  `b` 上被篡改的曲线副本 `n / gx / a` 都不变，不比较 `b` 就绕过了参数检查。
- `check_peer_public_key`：对方的**静态**与**临时**公钥都按 p256 自己的参数
  重算曲线方程 `y² = x·(x² − 3) + b`，并要求坐标规范（`< p`、拒绝 `(0,0)`），
  否则 `raise NotOnCurve`。

两点实现说明：

- 不直接复用 `point_is_on_curve_affine`：它的 `a·x` 项经 `bn_addmod_p` 计算，
  在部分输入上与后者的缺陷叠加会得到错误结论（见下方新增 **H4**）。
  `check_peer_point` 改用 `x·(x² − 3) + b` 的等价写法，全程只用 `bn_eq` /
  `bn_lt` 与「减 3」这一个必然可归约的 `bn_submod_p`。
- 公开 API 构造不出「`curve` 是 p256、坐标却不在 p256 上」的公钥
  （`public_key_from_xy` 会拒绝），因此黑盒测试
  `sm2_key_exchange_rejects_foreign_curve_keys` 覆盖参数不一致的
  `InvalidParameter` 路径（四个入口位置 + 本方私钥），而 `NotOnCurve` 路径由
  白盒测试 `check_peer_point_rejects_off_curve_inputs` 直接覆盖，另有
  `same_curve_compares_every_parameter` 锁定六项逐一比较。
- 顺带修了 M2 中 `sm2_p256()` 的 `n` / `gx`：现在每次调用都返回新数组，
  回归测试 `sm2_p256_returns_independent_arrays`。

全量测试 356/356 通过；`.mbti` 无变化。

### S4. 空 `uid` 语义在签名 / 验签 / 摘要三条路径上不一致【实测】
[sm2.mbt:208] `sm3_digest` 把空 uid 换成 `default_uid()`；
[sm2.mbt:276] `sm2_sign`、[sm2.mbt:452] `sm2_verify`、[sm2.mbt:188] `za`
则原样使用空串。gmsm 对 `Sm2Sign` 的空 uid 走默认值。

- 探针：`sm2_sign(sk, m, b"", rand)` 后
  `sm2_verify(pub, m, b"", r, s)` = true，
  但 `sm2_verify(pub, m, default_uid(), r, s)` = false，
  `sm2_verify_digest(pub, pub.sm3_digest(m, b""), r, s)` = false。
- 影响：README 的 Z 值 / 摘要验签示例（[README.mbt.md:214]）注释写着
  「uid 为空时等价于 default_uid()」，用户按此组合会出现「签名成功、验签失败」。
- 修法：在 `za` / `sm2_sign` / `sm2_verify` 统一「空 uid → default_uid」，
  或反过来取消 `sm3_digest` 的特判并修正文档。

**修复状态（2026-11-17）**：采用「签名 API 统一、`za` 保持原样」的方案。
原先假设的「gmsm 对空 uid 一律走默认值」并不成立于 `ZA`：gmsm 的
`sm2.ZA(pub, uid)` 对空 uid 是**原样哈希**（ENTLA = 0），向量
`go_sm2_za_empty-*`（由 gmsm oracle 生成）锁定了 `c13adcc1…` 这个值。
因此统一范围改为「签名 / 验签 / 摘要」三条路径：

- 新增私有 `uid_or_default`（[sm2/primitives.mbt:14]），`sm2_sign`（[sm2.mbt:324]）、
  `sm2_verify`（[sm2.mbt:506]）、`sm3_digest`（[sm2.mbt:248]）全部经由它取
  生效 uid；三条路径互相可替换，不再出现「签名成功、验签失败」。
- `SM2PublicKey::za` 恢复原样使用 uid（修复前就是如此），并在文档中写明
  「空 uid 原样使用、仅签名 API 才映射到默认值」，避免读者误用。
- `sm2_sign_der` / `sm2_verify_der` 只是转发，自动继承该语义。

回归测试 `sm2_empty_uid_means_default_uid_in_sign_verify_digest`
（[sm2/sm2_test.mbt:616]）覆盖四种交叉组合 + 摘要路径 + 非空 uid 不被吞掉 +
`za(空) ≠ za(默认)`；`go_sm2_za_empty-*` 四个向量保持原样通过。

全量测试 357/357 通过；`.mbti` 无变化。

---

## 🟠 高

### H1. `read_key_from_pem` 无格式认证，攻击者可指定明文密钥或降级到旧格式【读码】【已修复】
[sm4/utils.mbt:139-157]：只去掉 `Proc-Type` 头、保留块类型 `SM4 KEY`，
即可让函数**原样返回**攻击者写入的 16 字节；保留 `SM4 ENCRYPTED KEY`、
把 `DEK-Info` 换成 `AES-256-CBC,<iv>` 则自动走无 MAC 的 legacy 路径。
认证只覆盖安全格式的 `c‖tag`，不覆盖头部与块类型。

- 修法：增加 `require_encrypted` / `strict` 入口（拒绝明文块、禁用 legacy
  自动降级），并在函数文档中写明「本函数只负责解码，不保证来源可信」。

**修复状态（2026-11-17）**：新增读取策略与严格入口，`read_key_from_pem`
签名不变（内部转发到 `read_key_from_pem_strict(…, AcceptAny)`）。

- `pub(all) enum Sm4PemReadPolicy { AcceptAny, EncryptedOnly }`
  （[sm4/utils.mbt]），`read_key_from_pem_strict(data, pwd, policy)` 为公开
  入口。`EncryptedOnly` 要求：块类型为 `SM4 ENCRYPTED KEY`、
  `Proc-Type: 4,ENCRYPTED`、`DEK-Info` 为三字段安全格式、口令非空；明文
  `SM4 KEY` 与 `AES-256-CBC` 旧格式（含把安全格式头部改成旧格式的降级）
  一律 `raise InvalidData`，不存在自动降级。
- 头部字段本身不参与 MAC 的客观事实写进了两个函数的文档：「读取成功」
  只有在 `EncryptedOnly` 下才等于「文件未被篡改」；宽松入口明示
  「只负责解码，不保证来源可信」。
- 测试：`sm4_pem_strict_rejects_plaintext_block`（攻击者明文块与自写明文块
  均被拒、宽松入口确实接受以证明必要性）、
  `sm4_pem_strict_rejects_legacy_downgrade`、
  `sm4_pem_strict_rejects_missing_proc_type`、
  `sm4_pem_strict_accepts_secure_format`；README 增补说明与示例。

全量测试 361/361 通过；`.mbti` 新增 `Sm4PemReadPolicy` 与
`read_key_from_pem_strict`（纯增量）。

### H2. legacy PEM 口令长度语义与 Go 相反，长口令文件无法互通，错误语义不一致【读码】
[aes.mbt:342-347] `pem_legacy_key` 在 `pwd.length() > 32` 时 `raise InvalidData`，
而同文件注释与 Go `x509.EncryptPEMBlock` 都是**截断到 32 字节**。

- 同样，legacy 解密（[sm4/utils.mbt:528-540]）把「解密失败」和「填充错误」都
  映射为 `InvalidPadding`，属于无认证 CBC 的 padding-oracle 结构；`pkcs7_unpad_key`
  循环长度随 `tail` 变化，也不是常量时间。
- 修法：恢复截断语义；旧格式入口文档标注「仅供导入，导入后立即用安全格式重写」。

### H3. `sm2_sign` 私钥 d 的标量乘法是分支相关的，存在时序侧信道【读码】
[curve.mbt:313-389] `scalar_mult` 的 wNAF 迭代按标量位决定是否调用
`point_add_affine`，`sm2_sign` / `sm2_decrypt` / `key_exchange_*` 都直接用它处理
私钥标量。`spec_001_SM2.md` 明确说「不做常量时间保证」——但 README 通篇强调
安全加固，两者给人的预期相反。

- 修法（择一）：① 在 README / `safe.md` 顶部显式声明「非常量时间，勿用于
  可被同机计时的场景」；② 对 d 做标量 / 坐标盲化。

### H4. `bn_addmod_p` 在「和恰为 p」时返回 p 而不是 0，`bn_submod_p` 的借位分支不可用【实测】【未修复】
修 S3 时发现，这是比 S3 更底层的缺陷。

- `bn_addmod_p`（[sm2/bn.mbt:493]）用 `bn_sub(r, r, p)` 处理「有进位或
  `r >= p`」的情形，但 `bn_sub` 只处理 4 limb，**进位被丢弃**。当 `a + b == p`
  时 `r` 恰好等于 `p`，相减得到 0 并返回借位，落进位没有被抵消，最终留下
  `p`（即 0 的非规范表示）。最小复现：`bn_addmod_p(x3, 1)` 再
  `bn_addmod_p(x3, b)`，其中 `x3 + 1 ≡ 0 (mod p)`——结果是 `p` 而不是 `b`。
- `bn_submod_p` 的借位分支同样丢借位：`0 - 1 mod p` 在本轮修复前的实现里
  返回 `2^256 - 1`（应返回 `p - 1`）。
- 影响：`point_is_on_curve_affine`（[sm2/curve.mbt:70]）对这类输入给出错误
  结论——`public_key_from_xy` / `is_on_curve` 会把真正在曲线上的点判为不在
  曲线上，`sm2_decrypt` 的 C1 检查、`public_key_from_xy` 的构造校验都会随之
  误拒。由于这些误判依赖具体坐标，属于输入相关的隐性失败，而不是稳定行为。
- 本轮处置：S3 的新检查绕开了这两条路径（见 S3 的修复说明）；`bn` 层本身
  **未改**，留待专项处理。修法：`bn_addmod_p` / `bn_submod_p` 用带第 5 limb
  的加减法（或 `bn_add` / `bn_sub` 返回的进位/借位手工维护）完成规约，并为
  `(p-1)+1`、`0-1`、`a+b == p` 等边界补回归测试。

---

## 🟡 中

### M1. 97 字节密文存在「截掉 C2 得到空明文」的歧义【实测】
[sm2.mbt:675] 只要求 `cipher.length() >= 97`。C1C3C2 下 C2 = `cipher[97:]`，
截断到 97 字节后 C2 为空、KDF 输出为空、C3 恰好匹配空明文。

- 探针：加密空消息得到 97 字节 → 截到 97 字节 → `sm2_decrypt` 成功返回
  `len=0`。（加密非空消息再截断会被 C3 拒绝；密钥协商没有此类问题。）
- 修法：加密端拒绝空明文（GM/T 0003 要求消息长度 ≥ 1），或解密端要求
  C2 非空；`sm2_encrypt_asn1` / `cipher_marshal` 同步收紧。C1C2C3 的
  `c3 = cipher[65+cl:]` 也应要求恰好 32 字节。

### M2. `SM2Curve` / `SM2Point` 仍可被外部任意改写或凭空构造【读码】
上次提交（`7e64562`）只收紧了 `SM2PrivateKey` / `SM2PublicKey` 的字段，但：
- `SM2PublicKey::curve()` / `SM2PrivateKey::curve()` 返回的是**内部共享的**
  `SM2Curve`（`pub(all)`，[sm2.mbt:8]），调用方改写 `curve.n[0]` 会影响该密钥
  后续所有运算——「拷贝式访问」没有落实到 curve 上。
- `SM2Point` 仍是 `pub(all)`（[curve.mbt:6]），外部可以构造任意 Jacobian 点。

- 修法：`curve()` 返回深拷贝或改为不可变的抽象；`SM2Point` 去掉 `pub(all)`。
  这条是破坏性 API 变更，建议尽早做。

### M3. `wipe()` 之后的密钥/密码对象继续静默工作【读码，旧结论仍成立】
[sm2.mbt:1050] `SM2PrivateKey::wipe`、[sm4/cipher.mbt:75] `SM4Cipher::wipe`
文档都说「之后不可用」，但没有置位标志；用擦除后的 d 签名、解密、派生公钥
都会得到错误结果而不报错。

- 修法：加 `wiped : Bool` 字段，后续所有入口检查后 `raise`。

### M4. `SM4Cipher` 的轮密钥字段对外可读；`SM4Key = Bytes` 打印即泄露密钥【读码】
`SM4Cipher.rk` / `rk_rev` 是 `pub struct` 的私有字段不错，但 `pkg.generated.mbti`
显示类型本身 `pub`，包内共享；更实际的风险是 `SM4Key` 是 `Bytes` 别名，
`println(key)` / 字符串插值会把 16 字节密钥原样打到日志。`sm3` 没有
`hmac_verify` 之类的常量时间入口，`byteutil.bytes_eq` 又会被误用为 MAC 比较。

- 修法：README 增加「密钥/口令不要进日志」的警告；`sm3` 补
  `hmac_sm3_verify`（内部 `ct_eq`）；`SM4Cipher` 增加 `wipe` 之外的不可复制性
  说明。

### M5. GCM「与 OpenSSL / BoringSSL / Go 互通」的表述过强；legacy 变体没有跨语言向量【读码】
- [sm4/sm4.mbt:765] 只接受恰好 16 字节 tag，而 BoringSSL / 部分平台默认用
  12 字节截断 tag。真实互通的只有「完整 tag + 96 位 nonce」。
- `sm4_gcm_encrypt_legacy` 的「与 gmsm 逐字节一致」承诺，测试里只用了全零
  16 字节 IV——这种 IV 下字节长度与比特长度拼进长度块后前 56 位都是 0，
  legacy 差异路径（0xff 进位、非 16 字节 IV）根本没有被覆盖。
- 空 nonce / 任意长度 nonce 都被接受（文档已说明 96 位以外走 GHASH 派生 J0），
  没有 nonce 复用保护。
- 修法：README 改为「与标准 GCM 在 96 位 nonce + 16 字节 tag 下互通」；
  用 gmsm 生成 12 字节 IV、0xff 结尾计数器、>256 字节明文的 KAT 补进
  `baseline-go`。

### M6. `pem_encode` 不校验头部，可注入伪 `-----END` 行【读码】
[byteutil/pem.mbt:43-55] 原样拼接 header 的 key/value；value 含 `\n` 即可
伪造结束行或额外头部（`sm4` 的 `get_header` 取**第一个**匹配，注入在前会被
优先使用）。`pem_encode` 是公开 API，调用方的用户输入会直达。

- 修法：key/value 拒绝 `\n`、`\r`、空 key；写入前做一次 round-trip 自检。

### M7. `pkcs7_pad` 无参数校验；`pkcs7_unpad` 非常量时间【读码】
[byteutil/pkcs7.mbt:22] `block_size == 0` 时除零 panic；`block_size > 256`
时 `to_byte()` 截断，静默产生非法填充。[pkcs7.mbt:46-63] 遇到第一个不一致
字节即 `raise`，可观测的提前返回。

- 修法：`pad` 增加 `1 <= block_size <= 255` 校验；`unpad` 改为累积差之后
  统一抛出。

### M8. `key_exchange_*` 不校验 `klen`；`sm2_sign` 的 `k` 重试无上界【读码】
- `klen = 0` 成功返回空密钥；`klen = -5` 被误报为 `KdfZeroKey`
  （[sm2.mbt:864]、[primitives.mbt:86]）。应在入口 `raise InvalidParameter`。
- [bn.mbt:674]、[sm2.mbt:152]、[sm2.mbt:295] 三处 `while true` 无重试上限，
  坏随机源会让调用挂起（与 S1 同源）。

---

## 🟢 低 / 文档与实现不一致

| 位置 | 问题 | 建议 |
| --- | --- | --- |
| [README.mbt.md:55] | 「`base64_decode` 接受省略 padding，与 Go `base64.StdEncoding` 的读取端一致」——Go `StdEncoding.DecodeString` **拒绝**无 padding（`RawStdEncoding` 才接受） | 改为「比 Go `StdEncoding` 更宽松，对齐 `RawStdEncoding`」 |
| [README.mbt.md:21] | 「不会 abort / panic」——[hexutil.mbt:36] `pub fn hex_nibble` 直接 abort（且已是死代码）；[byteutil.mbt:166] `xor_bytes` 长度不等即 abort | `hex_nibble` 改私有或返回 `Int?`；`xor_bytes` 改 `raise` |
| [README.mbt.md:30] | SM3 段未提 `hmac_sm3` / `pbkdf2_hmac_sm3`（只在 gap_analysis 里提过）；「对齐 Go `hash.Hash`」但 `sum` 语义与 Go 的 `Sum(prefix)` 不同 | 补 HMAC/PBKDF2 小节，修正对齐表述 |
| [README.mbt.md:43-51] | 未说明默认 PBKDF2 60 万次迭代约 2.5 秒 | 标出耗时与「可调但仍偏慢」 |
| [docs/gap_analysis.md:232] | 「A7 的口令加密格式与 gmsm 完全一致（AES-256-CBC）」与本节 146 行「默认已改为安全格式」自相矛盾 | 删除/改写这段残留说明 |
| [docs/spec/spec_002_SM4.md:32] | 「不实现 GCM、CTR、OFB、CFB」已过时；`sm4_expand_key(key, mode)` 签名与实现不符 | 更新规范 |
| [docs/spec/spec_001_SM2.md:96] | k 生成写成 `rand mod (n-1) + 1`，实现是拒绝采样 | 更新规范 |
| [sm2/sm2_wbtest.mbt:846] | 测试名 `panic_za_uid_too_long` 与注释说 abort，实际是 `raise` | 改名 |
| [byteutil/asn1.mbt:49-59] | 文档说调用方「MUST 检查 `content_end`」，又说这是 strict 检查；短格式长度确实不查越界 | 统一行为或措辞 |
| [sm4/aes.mbt:7] | 注释称 "table-free"，实际是查表 S 盒（缓存时序侧信道） | 修正注释 |
| [byteutil/pem.mbt:199] | body 循环按 `-----END ` 前缀判结束，正文行可以伪造结束行、尾随内容被静默丢弃 | 要求整行严格等于 `-----END <type>-----`，其余报错 |
| [cipher.mbt:165] | `sm4_ecb/cbc/cfb/ofb` 使用包级默认 IV（默认全零），README 仍推荐 | 加 `#deprecated` 或改成必须传 IV |
| [cmd/sm2/main.mbt:12] | 示例打印私钥 hex 到 stdout，虽有注释，仍容易被复制到生产 | 改为只打印长度/指纹 |
| [sm4/utils.mbt:102] | `sm4_pem_max_iterations = 10_000_000` 意味着一个被篡改的 PEM 头可以让解密卡住几十秒 | 读取端单独设更低上限（如 1M） |

---

## 已核对的正确项

- SM2 签名的 k 取随机、`r = 0` / `r + k ≡ 0` 的重试；`verify_with_e` 的 r/s
  范围检查；C3 比较走 `ct_eq`；解密三种失败统一 `InvalidCipher`。
- ZA 的 ENTLA 编码、uid ≥ 8192 拒绝。
- SM3 流式状态与一次性结果一致；HMAC 长密钥先哈希；PBKDF2 与 Python
  `hashlib.pbkdf2_hmac('sm3', …)` 逐字节一致，迭代 0 被拒绝。
- ASN.1 长度解码拒绝 `0x80`、`>4` 字节长格式、非最小编码、越界；
  `normalize_32` 拒绝冗余前导零。
- GCM 标准实现的 GHASH、J0、计数器进位、长度块（64 位）正确；legacy 变体
  确实复刻了 gmsm 的两处非标准行为；`ct_eq` 校验 tag 后才返回明文。
- `sm2_encrypt` 对非空消息的截断会被 C3 拒绝（只有空明文这一角落有
  歧义，见 M1）。
