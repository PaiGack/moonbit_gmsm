# SM4 MoonBit 移植规范

> 本文件描述 `PaiGack/gmsm/sm4` 包的实现规划、API 契约、测试数据与测试方案。
> 实现目标：与 Go 生态中的 [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm)（Apache-2.0）按
> `gmsm/sm4/sm4.go` 在功能与测试向量上对齐。

## 全局规则

- go 版本的 tjfoc/gmsm 不需要看 github 的远端代码库，代码就在 `gmsm` 里面
- SM4 分组密码算法，参照 GM/T 0002-2012《SM4 分组密码算法》

## 1. 范围与目标

### 1.1 覆盖范围

参照 `gmsm/sm4/sm4.go` 暴露的全部公开能力：

| 能力域 | gmsm 函数 | 本包对应 API |
| --- | --- | --- |
| 分组加密 | `Sm4Encrypt(key, data)` | `sm4_encrypt_block(key, plain) -> Bytes` |
| 分组解密 | `Sm4Decrypt(key, data)` | `sm4_decrypt_block(key, cipher) -> Bytes` |
| 密钥扩展 | `expandKey(key, enc/dec)` | `sm4_expand_key(key, mode)`（内部） |
| ECB 加密 | `Sm4Ecb(key, data)` 通过多次调用 | `sm4_encrypt_ecb(key, data) -> Bytes` |
| ECB 解密 | `Sm4Ecb(key, data)` 通过多次调用 | `sm4_decrypt_ecb(key, data) -> Bytes` |
| CBC 加密 | `Sm4Cbc(key, iv, data)` | `sm4_encrypt_cbc(key, iv, data) -> Bytes` |
| CBC 解密 | `Sm4Cbc(key, iv, data)` | `sm4_decrypt_cbc(key, iv, data) -> Bytes` |
| 填充（PKCS7） | 上层自行处理 | `pkcs7_pad(data, block_size)` / `pkcs7_unpad(data)`（可选辅助） |
| S-Box | 内部常量 `sbox[256]` | 内部常量 `SBOX` |

### 1.2 非目标

- 不实现 GCM、CTR、OFB、CFB 等工作模式（gmsm 的 `sm4.go` 也仅含 ECB / CBC）；
- 不做侧信道（constant-time）保证；首版以「正确性 + 与 gmsm 互操作」为优先；
- 不实现硬件加速（AES-NI / ARM CE），纯软件路径。

### 1.3 标准依据

- GM/T 0002-2012《SM4 分组密码算法》；
- SM4 实施参考：`tjfoc/gmsm/sm4`；
- SM4 标准测试向量来自 GM/T 0002-2012 附录 A。

## 2. 架构分层

SM4 为对称分组密码，结构比 SM2 简单。所有代码放在一个文件内：

```
sm4/
├── sm4.mbt          // SM4 全部实现（分组加密/解密、ECB、CBC、密钥扩展）
├── sm4_test.mbt     // 黑盒测试
├── sm4_wbtest.mbt   // 白盒测试（S-Box、密钥扩展、单分组加密/解密）
└── moon.pkg         // 依赖：moonbitlang/core/bytes
```

### 2.1 SM4 算法概述

SM4 是 Feistel 结构的分组密码：

- **分组长度**：128-bit（16 字节）
- **密钥长度**：128-bit（16 字节）
- **轮数**：32 轮
- **轮函数 F**：`F(X0, X1, X2, X3, rk) = X0 ⊕ T(X1 ⊕ X2 ⊕ X3 ⊕ rk)`
  - 其中 `T` = 合成置换 = `L(τ(.))`
  - `τ`：S-Box 非线性变换（4 个并行的 8×8 S-Box）
  - `L`：线性变换 `L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)`
- **反序**：解密使用轮密钥的逆序（`rk[31], rk[30], ..., rk[0]`）

### 2.2 常量定义

#### 2.2.1 S-Box

SM4 S-Box 是一个 256 字节的固定置换表（来自 GM/T 0002-2012，与 gmsm `sm4.go:12-19` 一致）：

```text
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
```

#### 2.2.2 系统参数 FK

密钥扩展使用的系统参数 `FK = (FK0, FK1, FK2, FK3)`，每个 32-bit（GM/T 0002-2012 附录 A.1）：

```text
FK0 = A3B1BAC6
FK1 = 56AA3350
FK2 = 677D9197
FK3 = B27022DC
```

#### 2.2.3 固定参数 CK

密钥扩展使用的 32 个固定参数 `CK[0..31]`，每个 32-bit（GM/T 0002-2012 附录 A.2）：

```text
CK[0]  = 00070E15  CK[1]  = 1C232A31  CK[2]  = 383F464D  CK[3]  = 545B6269
CK[4]  = 70777E85  CK[5]  = 8C939AA1  CK[6]  = A8AFB6BD  CK[7]  = C4CBD2D9
CK[8]  = E0E7EEF5  CK[9]  = FC030A11  CK[10] = 181F262D  CK[11] = 343B4249
CK[12] = 50575E65  CK[13] = 6C737A81  CK[14] = 888F969D  CK[15] = A4ABB2B9
CK[16] = C0C7CED5  CK[17] = DCE3EAF1  CK[18] = F8FF060D  CK[19] = 141B2229
CK[20] = 30373E45  CK[21] = 4C535A61  CK[22] = 686F767D  CK[23] = 848B9299
CK[24] = A0A7AEB5  CK[25] = BCC3CAD1  CK[26] = D8DFE6ED  CK[27] = F4FB0209
CK[28] = 10171E25  CK[29] = 2C333A41  CK[30] = 484F565D  CK[31] = 646B7279
```

> `CK[i][j] = (4i + j) × 7 mod 256`（i=0..31, j=0..3，与 gmsm `sm4.go:28-35` 一致）。

### 2.3 数据表示与字节序

| 元素 | 表示 | 字节序 | 说明 |
| --- | --- | --- | --- |
| 分组数据（明文/密文） | `Bytes` | 大端（MSB first） | 16 字节一组，`X0` = `data[0..4]`, `X1` = `data[4..8]`, `X2` = `data[8..12]`, `X3` = `data[12..16]` |
| 密钥 | `Bytes` | 大端 | 16 字节，`MK0` = `key[0..4]`, `MK1` = `key[4..8]`, `MK2` = `key[8..12]`, `MK3` = `key[12..16]` |
| IV（CBC 模式） | `Bytes` | 大端 | 16 字节 |
| 32-bit 字 | `UInt`（MoonBit） | 与大端字节序互转 | `get_u32_be(b, off)` / `put_u32_be(b, off, v)` |
| 轮密钥 `rk[0..31]` | `FixedArray[UInt]`（长度 32） | 内部表示 | 每个元素为 32-bit |

### 2.4 核心算法

#### 2.4.1 轮函数 F

```
F(X0, X1, X2, X3, rk) = X0 ⊕ T(X1 ⊕ X2 ⊕ X3 ⊕ rk)
```

其中 `T` 为合成置换，输入与输出均为 32-bit 字：

```
T(A) = L(τ(A))
```

#### 2.4.2 S-Box 变换 τ

输入 32-bit 字 A，拆为 4 字节 `(a0, a1, a2, a3)`（`a0` 为最高字节），各经 S-Box 查表：

```
τ(A) = (SBOX[a0] << 24) | (SBOX[a1] << 16) | (SBOX[a2] << 8) | SBOX[a3]
```

#### 2.4.3 线性变换 L（用于加密轮函数）

```
L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)
```

其中 `<<<` 为 32-bit 循环左移。

#### 2.4.4 线性变换 L'（用于密钥扩展）

```
L'(B) = B ⊕ (B <<< 13) ⊕ (B <<< 23)
```

#### 2.4.5 密钥扩展算法

1. `(MK0, MK1, MK2, MK3) = 128-bit 密钥`（每 4 字节为一个 32-bit 大端字）
2. `(K0, K1, K2, K3) = (MK0 ⊕ FK0, MK1 ⊕ FK1, MK2 ⊕ FK2, MK3 ⊕ FK3)`
3. 对 `i = 0..31`：
   - `rk[i] = K_(i+4) = K_i ⊕ T'(K_(i+1) ⊕ K_(i+2) ⊕ K_(i+3) ⊕ CK[i])`
   - 其中 `T'` = `L'(τ(.))`（注意：密钥扩展中用 **L'** 而非 L）

#### 2.4.6 加密过程

输入：128-bit 明文 `(X0, X1, X2, X3)` 和轮密钥 `rk[0..31]`

对 `i = 0..31`：
```
X_(i+4) = F(X_i, X_(i+1), X_(i+2), X_(i+3), rk[i])
```

输出密文 `(Y0, Y1, Y2, Y3) = (X_35, X_34, X_33, X_32)`（逆序）。

#### 2.4.7 解密过程

解密与加密完全一致，仅轮密钥使用顺序相反：
- 加密：`rk[0], rk[1], ..., rk[31]`
- 解密：`rk[31], rk[30], ..., rk[0]`

#### 2.4.8 PKCS7 填充

与 gmsm 的 `sm4.go` 不同，MoonBit 实现额外提供 PKCS7 填充辅助函数（gmsm 留给调用方处理）：

```mbt
pub fn pkcs7_pad(data : Bytes, block_size : Int = 16) -> Bytes
pub fn pkcs7_unpad(data : Bytes) -> Bytes raise SM4Error
```

PKCS7 规则：填充字节值为需要填充的字节数。例如数据长度 10、block_size 16，则填充 6 个值为 `0x06` 的字节。

## 3. API 设计

### 3.1 公开类型与错误

```mbt
///|
pub suberror SM4Error {
  InvalidKey       // 密钥长度 ≠ 16 字节
  InvalidData      // 数据长度不是 16 的倍数（ECB/CBC 分组输入）
  InvalidIV        // IV 不为空且长度 ≠ 16 字节
  InvalidPadding   // PKCS7 去填充时填充值不合法
  DecryptFailed    // CBC 解密失败（用于广义错误）
} derive(Show, Eq)
```

### 3.2 公开函数

```mbt
/// 单分组加密：key、data 各 16 字节，返回 16 字节密文
pub fn sm4_encrypt_block(key : Bytes, data : Bytes) -> Bytes raise SM4Error

/// 单分组解密：key、data 各 16 字节，返回 16 字节明文
pub fn sm4_decrypt_block(key : Bytes, data : Bytes) -> Bytes raise SM4Error

/// ECB 模式加密：data 长度须为 16 的倍数
pub fn sm4_encrypt_ecb(key : Bytes, data : Bytes) -> Bytes raise SM4Error

/// ECB 模式解密：data 长度须为 16 的倍数
pub fn sm4_decrypt_ecb(key : Bytes, data : Bytes) -> Bytes raise SM4Error

/// CBC 模式加密：iv 为 16 字节（可为空，为空时报错）
pub fn sm4_encrypt_cbc(key : Bytes, iv : Bytes, data : Bytes) -> Bytes raise SM4Error

/// CBC 模式解密：iv 为 16 字节，data 长度须为 16 的倍数
pub fn sm4_decrypt_cbc(key : Bytes, iv : Bytes, data : Bytes) -> Bytes raise SM4Error

/// PKCS7 填充
pub fn pkcs7_pad(data : Bytes, block_size : Int) -> Bytes

/// PKCS7 去填充
pub fn pkcs7_unpad(data : Bytes) -> Bytes raise SM4Error
```

### 3.3 ECB 模式

```
加密：cipher = sm4_encrypt_block(key, plain[i*16 .. (i+1)*16])  // 逐分组
解密：plain  = sm4_decrypt_block(key, cipher[i*16 .. (i+1)*16]) // 逐分组
```

### 3.4 CBC 模式

```
加密：
  C0 = IV
  C_i = sm4_encrypt_block(key, P_i ⊕ C_(i-1))
解密：
  C0 = IV
  P_i = sm4_decrypt_block(key, C_i) ⊕ C_(i-1)
```

> 与 gmsm `Sm4Cbc` 行为一致（gmsm `sm4.go:110-141`）。

## 4. 测试数据来源

### 4.1 GM/T 0002-2012 标准测试向量（附录 A）

以下测试向量来自 GM/T 0002-2012 标准附录 A，用于验证单分组加密/解密正确性。

#### 4.1.1 加密 KAT 1

```text
密钥 (key)：  01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
明文 (plain)：01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
密文 (cipher)：68 1E DF 34 D2 06 96 5E 86 B3 E9 4F 53 6E 42 46
```

#### 4.1.2 加密 KAT 2（重复加密 1,000,000 次）

> 本 KAT 仅用于性能/稳定性压测，首版不强制通过；可放到 M2 后续补。

```text
密钥 (key)：  01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
明文 (plain)：01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
// 将上一次输出作为下一次输入，迭代 1,000,000 次
密文 (cipher)：59 52 98 C7 C6 FD 27 1F 04 02 F8 04 C3 3D 3F 66
```

### 4.2 自定义 ECB / CBC 测试向量

以下向量通过 gmsm Go 实现生成（`zeroIV` = 16 字节全 0，pkcs7 填充）：

```text
密钥：01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
IV：  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

#### 4.2.1 ECB + PKCS7 加密

| 明文 hex | 填充后明文 hex | 密文 hex |
| --- | --- | --- |
| （空） | `10101010101010101010101010101010`（仅填充） | `TBD_由 gmsm Go 生成` |
| `313233343536`（"123456"） | `3132333435360A0A0A0A0A0A0A0A0A0A` | `TBD_由 gmsm Go 生成` |
| `31323334353637383930313233343536`（"1234567890123456"，刚好 16 字节） | `3132333435363738393031323334353610101010101010101010101010101010` | `TBD_由 gmsm Go 生成` |

#### 4.2.2 CBC + PKCS7 加密

| 明文 | 填充后明文 | 密文 hex（`iv = zeroIV`） |
| --- | --- | --- |
| （空） | `10101010101010101010101010101010` | `TBD_由 gmsm Go 生成` |
| `313233343536`（"123456"） | `3132333435360A0A0A0A0A0A0A0A0A0A` | `TBD_由 gmsm Go 生成` |

> **M2 强制验收项**：实施 ECB/CBC 时，必须先用 gmsm Go 实现生成上述 KAT，填入上表。

### 4.3 互操作验证路径

与 gmsm 的互操作通过以下路径保证：

1. 单分组加密/解密：与 GM/T 0002-2012 标准附录 A 测试向量字节级一致（§4.1.1）；
2. ECB/CBC 加密/解密：与 gmsm `Sm4Ecb` / `Sm4Cbc` 在相同密钥、IV、明文下输出字节级一致（§4.2）。

## 5. 测试方案

测试分布在两个文件：

| 文件 | 范围 | 类型 |
| --- | --- | --- |
| `sm4/sm4_wbtest.mbt` | 白盒（包内）：S-Box、τ 变换、L 变换、L' 变换、密钥扩展、单分组加密/解密 | assertion + KAT |
| `sm4/sm4_test.mbt` | 黑盒（公开 API）：ECB、CBC、PKCS7 填充、错误路径 | assertion + KAT |

### 5.1 白盒单测

`sm4/sm4_wbtest.mbt`：

1. **S-Box**
   - `SBOX[0x00] == 0xD6`、`SBOX[0xFF] == 0x48` 等边界值校验。

2. **τ 变换**
   - `τ(0x01234567) = (SBOX[0x01] << 24) | (SBOX[0x23] << 16) | (SBOX[0x45] << 8) | SBOX[0x67]`。

3. **L 变换**
   - 固定输入验证循环左移组合：`L(0x01234567) = 0x01234567 ⊕ ROL(0x01234567, 2) ⊕ ROL(0x01234567, 10) ⊕ ROL(0x01234567, 18) ⊕ ROL(0x01234567, 24)`。

4. **L' 变换**
   - `L'(0x01234567) = 0x01234567 ⊕ ROL(0x01234567, 13) ⊕ ROL(0x01234567, 23)`。

5. **密钥扩展**
   - 用 §4.1.1 密钥 `0123456789ABCDEFFEDCBA9876543210` 做密钥扩展，验证 `rk[0]`、`rk[31]` 与 gmsm 生成的一致。

6. **单分组加密 KAT**
   - `sm4_encrypt_block(KAT_key, KAT_plain) == KAT_cipher`（§4.1.1）；
   - `sm4_decrypt_block(KAT_key, KAT_cipher) == KAT_plain`（§4.1.1）。

7. **round-trip**
   - 随机 16 字节密钥 + 随机 16 字节明文：`decrypt(key, encrypt(key, data)) == data`。

### 5.2 黑盒集成测试

`sm4/sm4_test.mbt`：

1. **ECB round-trip**
   - 随机 16 字节密钥 + 随机 32 字节明文：`sm4_decrypt_ecb(key, sm4_encrypt_ecb(key, data)) == data`；
   - 数据长度非 16 倍数 → `SM4Error::InvalidData`。

2. **CBC round-trip**
   - 随机 16 字节密钥 + 随机 16 字节 IV + 随机 32 字节明文：`sm4_decrypt_cbc(key, iv, sm4_encrypt_cbc(key, iv, data)) == data`。

3. **PKCS7 填充**
   - `pkcs7_unpad(pkcs7_pad(b"hello", 16)) == b"hello"`；
   - 填充 16 字节全为 `0x10` 的数据 → unpad 返回空 `b""`；
   - 非法填充（如末端为 `0xFF`）→ `SM4Error::InvalidPadding`。

4. **错误路径**
   - 密钥长度 ≠ 16 → `SM4Error::InvalidKey`；
   - ECB 输入长度非 16 倍数 → `SM4Error::InvalidData`；
   - CBC IV 长度 ≠ 16 → `SM4Error::InvalidIV`；
   - CBC 解密输入长度非 16 倍数 → `SM4Error::InvalidData`。

### 5.3 错误路径覆盖矩阵

| 错误条件 | API | 期望错误 |
| --- | --- | --- |
| `key.length() != 16` | 所有 API | `SM4Error::InvalidKey` |
| `data.length() % 16 != 0` | `sm4_encrypt_ecb` / `sm4_decrypt_ecb` | `SM4Error::InvalidData` |
| `iv.length() != 16`（且 IV 非空） | `sm4_encrypt_cbc` / `sm4_decrypt_cbc` | `SM4Error::InvalidIV` |
| `data.length() % 16 != 0` | `sm4_encrypt_cbc` / `sm4_decrypt_cbc` | `SM4Error::InvalidData` |
| PKCS7 填充值不合法 | `pkcs7_unpad` | `SM4Error::InvalidPadding` |
| PKCS7 填充值 > block_size（16） | `pkcs7_unpad` | `SM4Error::InvalidPadding` |
| PKCS7 最后 n 字节不完全等于 n | `pkcs7_unpad` | `SM4Error::InvalidPadding` |

## 6. 实施路线

| 里程碑 | 内容 | 验收 |
| --- | --- | --- |
| M1 核心加密 | `sm4/sm4.mbt`：S-Box、τ 变换、L 变换、L' 变换、密钥扩展、`sm4_encrypt_block`、`sm4_decrypt_block` | `moon check`、`moon test`；单分组 KAT（§4.1.1）字节级一致；round-trip 通过 |
| M2 工作模式 | `sm4/sm4.mbt`：ECB 加密/解密、CBC 加密/解密、PKCS7 辅助函数 | ECB/CBC round-trip 通过；与 gmsm 生成的 ECB/CBC KAT（§4.2）字节级一致；错误路径覆盖矩阵全通过 |
| M3 清理与文档 | `moon info && moon fmt` 无 diff | 代码整洁、接口文件 `.mbti` 稳定 |

## 7. 测试数据文件约定

`sm4/testdata/`（白名单，提交到仓库）：

```text
sm4/testdata/
├── kat_enc_block.hex      // §4.1.1 加密 KAT（key ‖ plain ‖ cipher）
├── kat_ecb_empty.hex      // §4.2 空明文 ECB 密文（由 gmsm 生成）
├── kat_ecb_6bytes.hex     // §4.2 "123456" ECB 密文
├── kat_ecb_16bytes.hex    // §4.2 "1234567890123456" ECB 密文
├── kat_cbc_empty.hex      // §4.2 空明文 CBC 密文
└── kat_cbc_6bytes.hex     // §4.2 "123456" CBC 密文
```

> 注：KAT 需由 gmsm Go 实现生成后写入；本规范在实施阶段（M1/M2）完成前用硬编码常量替代，后续替换为 fixture 文件加载。

## 8. 实现细节建议

### 8.1 32-bit 字操作

MoonBit 的 `UInt` 类型适合 32-bit 运算，可直接用于 S-Box 查找和位操作。但需注意：

- **字节拆分**：从 `Bytes` 读取 32-bit 大端字时，`data[off]` 为最高字节：
  ```
  (data[off].to_uint() << 24) | (data[off+1].to_uint() << 16) | (data[off+2].to_uint() << 8) | data[off+3].to_uint()
  ```
- **循环左移**：`fn rotl(x : UInt, n : Int) -> UInt = (x << n) | (x >> (32 - n))`

### 8.2 L / L' 变换实现

```mbt
fn sm4_L(b : UInt) -> UInt {
  b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
}

fn sm4_L_prime(b : UInt) -> UInt {
  b ^ rotl(b, 13) ^ rotl(b, 23)
}
```

### 8.3 密钥扩展

特别容易出错的地方：密钥扩展使用 `L'`（不是 `L`），加密轮函数使用 `L`。参考 gmsm `sm4.go:84-102`。

```mbt
fn sm4_expand_key(key : Bytes, for_encrypt : Bool) -> FixedArray[UInt] {
  // 1. 拆 MK0..MK3
  // 2. K0..K3 = MK_i ⊕ FK_i
  // 3. 对 i=0..31: rk[i] = K_i ⊕ L'(τ(K_{i+1} ⊕ K_{i+2} ⊕ K_{i+3} ⊕ CK[i]))
  // 4. 若 !for_encrypt，逆序 rk
}
```

### 8.4 内部分组加密引擎

建议抽取内部函数 `sm4_process_block(X : FixedArray[UInt], rk : FixedArray[UInt]) -> FixedArray[UInt]`，供 `encrypt_block`、`decrypt_block`、ECB、CBC 复用。加密和解密共用一个引擎，仅轮密钥顺序不同。

## 9. 风险与开放问题

1. **UInt 字长兼容性**：MoonBit 的 `UInt` 在后端可能为 32-bit 或 64-bit。使用 `(x << n) | (x >> (32 - n))` 做循环左移时，若 `UInt` 为 64-bit，必须先 `& 0xFFFFFFFFU` 截断。首版通过 whitebox 单测（固定 32-bit 输入/输出）兜底，不依赖后端字长。

2. **性能**：SM4 纯软件实现性能预期为 ~10–50 MB/s（取决于后端）。如后续需要高性能，可考虑 wasm SIMD 或 native 后端向量化。

3. **PKCS7 填充**：gmsm 的 `sm4.go` 未提供 PKCS7，留给调用方处理。本实现提供辅助函数以提高易用性，但在与 gmsm 互操作时需注意——测试 ECB/CBC round-trip 之前需自行按 PKCS7 对齐输入长度。

## 10. 验收清单

- [ ] M1 单分组加密 KAT（§4.1.1）全部通过；
- [ ] M1 `sm4_encrypt_block` / `sm4_decrypt_block` round-trip 通过（随机 100+ 组）；
- [ ] M2 ECB 模式 round-trip 通过；
- [ ] M2 CBC 模式 round-trip 通过；
- [ ] M2 与 gmsm 生成的 ECB/CBC KAT 字节级一致（§4.2）；
- [ ] M2 PKCS7 填充 round-trip + 错误路径通过；
- [ ] M2 错误路径覆盖矩阵（§5.3）全部通过；
- [ ] M3 `moon info` 与 `moon fmt` 无 diff；
- [ ] M3 `moon test` 全绿。
