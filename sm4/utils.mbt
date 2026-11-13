/// SM4 密钥的 PEM 读写，对齐 gmsm 的 `sm4/utils.go`，并在其基础上加强
/// 口令加密的密钥派生。
///
/// - `read_key_from_pem` 对应 `ReadKeyFromPem`
/// - `write_key_to_pem` 对应 `WriteKeyToPem`
///
/// 未加密块类型为 `SM4 KEY`。带口令加密时，默认写出安全的
/// `SM4 ENCRYPTED KEY`（PBKDF2-HMAC-SM3 + SM4-CBC + HMAC-SM3 认证）；
/// 需要与 Go `x509.EncryptPEMBlock` / gmsm 互通时，可用
/// `write_key_to_pem_legacy` 显式写出旧格式，读取端始终兼容旧格式。
///
/// 安全格式布局：
///
/// ```text
/// Proc-Type: 4,ENCRYPTED
/// DEK-Info: SM4-CBC,PBKDF2-HMAC-SM3,<16 字节 salt 的大写十六进制>
/// SM4-KDF-Iterations: <迭代次数，十进制>
///
/// <encrypt-then-MAC 字节串>
/// ```
///
/// 其中
///
/// - `dk = PBKDF2-HMAC-SM3(口令, salt, iterations, 64)`；
/// - `K_e = dk[0:16]`，`K_m = dk[16:32]`；
/// - `iv = HMAC-SM3(K_m, "" ‖ "SM4-PEM-IV" ‖ salt)[0:16]`，由盐唯一确定，
///   不需要额外随机数；
/// - `c = SM4-CBC-Encrypt(K_e, iv, PKCS#7(密钥))`；
/// - `tag = HMAC-SM3(K_m, c)[0:32]`；
/// - 块内容为 `c ‖ tag`，解密时先做常量时间校验再解密。
///
/// 旧格式（仅用于互通）沿用 Go 旧版 `x509.EncryptPEMBlock` 的 RFC 1423
/// 布局，口令零填充成密钥且无盐、无迭代，**可被廉价暴力破解**：
///
/// ```text
/// Proc-Type: 4,ENCRYPTED
/// DEK-Info: AES-256-CBC,<16 字节 IV 的大写十六进制>
///
/// <AES-256-CBC(口令补零到 32 字节, IV) 加密的 PKCS#7 填充后的密钥>
/// ```

///|
/// 未加密 SM4 密钥的 PEM 块类型。
let sm4_key_pem_type : String = "SM4 KEY"

///|
/// 加密 SM4 密钥的 PEM 块类型。
let sm4_encrypted_key_pem_type : String = "SM4 ENCRYPTED KEY"

///|
/// 16 字节 SM4 密钥，对应 gmsm 的 `type SM4Key []byte`。
pub type SM4Key = Bytes

///|
/// 旧格式（RFC 1423 / `x509.EncryptPEMBlock`）的算法名。
let sm4_pem_legacy_cipher_name : String = "AES-256-CBC"

///|
/// 安全格式 `DEK-Info` 的第一个字段。
let sm4_pem_cipher_name : String = "SM4-CBC"

///|
/// 安全格式 `DEK-Info` 的第二个字段（KDF 名称）。
let sm4_pem_kdf_name : String = "PBKDF2-HMAC-SM3"

///|
/// 安全格式的迭代次数头部名。
let sm4_pem_iterations_header : String = "SM4-KDF-Iterations"

///|
/// 安全格式的默认 PBKDF2 迭代次数（OWASP 2023 对 PBKDF2-HMAC-SHA256
/// 建议 ≥ 600000，此处取同一量级）。
pub let sm4_pem_default_iterations : Int32 = 600000

///|
/// 允许的最大迭代次数，防止恶意文件把读取方拖入长时间计算。
pub let sm4_pem_max_iterations : Int32 = 10_000_000

///|
/// 允许的最小迭代次数。低于此值的文件不可能是本库写出的，接受它等于默默
/// 接受一个几乎不设防的口令加密格式，因此读取时直接拒绝。
pub let sm4_pem_min_iterations : Int32 = 100_000

///|
/// IV 派生的域分隔标签。
let sm4_pem_iv_label : Bytes = b"SM4-PEM-IV"

///|
/// 密钥长度（16 字节）与分组长度（16 字节）。
let sm4_pem_key_len : Int32 = 16

///|
/// 安全格式的 salt 长度（16 字节）。
let sm4_pem_salt_len : Int32 = 16

///|
/// 安全格式的认证标签长度（32 字节）。
let sm4_pem_tag_len : Int32 = 32

///|
/// PEM 口令加密格式。
pub(all) enum Sm4PemEncryption {
  /// PBKDF2-HMAC-SM3 + SM4-CBC + HMAC-SM3，安全默认值；参数为迭代次数。
  Pbkdf2HmacSm3(Int32)
  /// Go 旧版 `x509.EncryptPEMBlock` 格式，仅为与 gmsm 互通保留，不安全。
  LegacyX509
}

///|
#deprecated
pub extend Sm4PemEncryption with Eq::{not_equal, equal}

///|
pub impl Eq for Sm4PemEncryption with fn equal(self, other) {
  match (self, other) {
    (Pbkdf2HmacSm3(a), Pbkdf2HmacSm3(b)) => a == b
    (LegacyX509, LegacyX509) => true
    _ => false
  }
}

///|
/// 从 PEM 文本读取 SM4 密钥。加密块需要 `pwd`；未加密块忽略 `pwd`。
/// 对应 `ReadKeyFromPem(data, pwd)`。
///
/// 注意：未加密块（`SM4 KEY`）里就是明文密钥，传了 `pwd` 也**不会**解密，
/// 因此传口令并不代表内容被加密过；判断依据请用 `@byteutil.pem_decode`
/// 之后的 `Proc-Type` 头，或对 `SM4 ENCRYPTED KEY` 的块类型检查。
///
/// 加密块会按 `DEK-Info` 自动识别安全格式（`SM4-CBC,PBKDF2-HMAC-SM3,...`）
/// 或旧格式（`AES-256-CBC,...`）并解密；读取旧格式时不受时间攻击保护，
/// 应在迁移后重新用 `write_key_to_pem` 写出。
///
/// PEM 格式错误、块类型未知、加密块缺少口令、`DEK-Info` 缺失或格式错误
/// 时抛出 `SM4Error::InvalidData`；解密后填充不合法时抛出
/// `SM4Error::InvalidPadding`；安全格式的认证标签不匹配时抛出
/// `SM4Error::InvalidTag`；KDF 参数越界（如迭代次数过大）时抛出
/// `SM4Error::InvalidKdfParams`。
pub fn read_key_from_pem(data : String, pwd : Bytes) -> SM4Key raise SM4Error {
  let block = @byteutil.pem_decode(data) catch {
    _ => raise SM4Error::InvalidData
  }
  if is_encrypted_pem_block(block) {
    if block.type_ != sm4_encrypted_key_pem_type {
      raise SM4Error::InvalidData
    }
    if pwd.length() == 0 {
      raise SM4Error::InvalidData
    }
    decrypt_pem_block(block, pwd)
  } else {
    if block.type_ != sm4_key_pem_type {
      raise SM4Error::InvalidData
    }
    block.bytes
  }
}

///|
/// 把 SM4 密钥编码成 PEM。`pwd` 非空时用安全格式（PBKDF2-HMAC-SM3 +
/// SM4-CBC + HMAC-SM3 认证）加密，块类型为 `SM4 ENCRYPTED KEY`；
/// 否则块类型为 `SM4 KEY`。对应 `WriteKeyToPem(key, pwd)`。
///
/// `random` 用于生成加密用的 salt，加密时必须提供安全播种的生成器；
/// 传 `None` 会抛出 `MissingRandomSource`（不再有共享的固定种子兜底）。
/// `pwd` 为空时不产生随机数，可传 `None`。
pub fn write_key_to_pem(
  key : SM4Key,
  pwd : Bytes,
  random : @random.Rand?,
) -> String raise SM4Error {
  write_key_to_pem_with(
    key,
    pwd,
    random,
    Sm4PemEncryption::Pbkdf2HmacSm3(sm4_pem_default_iterations),
  )
}

///|
/// 按指定格式写出 SM4 密钥 PEM。`pwd` 为空时忽略 `encryption`，写出
/// 未加密的 `SM4 KEY`。
///
/// `Sm4PemEncryption::LegacyX509` 仅用于与 Go / gmsm 互通：口令被零填充
/// 成 AES-256-CBC 密钥，无盐无迭代，任何拿到文件的人都能低成本破解。
/// 新代码应使用 `write_key_to_pem`。
pub fn write_key_to_pem_with(
  key : SM4Key,
  pwd : Bytes,
  random : @random.Rand?,
  encryption : Sm4PemEncryption,
) -> String raise SM4Error {
  if key.length() != sm4_key_size {
    raise SM4Error::InvalidKey
  }
  if pwd.length() == 0 {
    return @byteutil.pem_encode_simple(sm4_key_pem_type, key)
  }
  match encryption {
    Pbkdf2HmacSm3(iterations) => {
      if iterations < sm4_pem_min_iterations ||
        iterations > sm4_pem_max_iterations {
        raise SM4Error::InvalidKdfParams
      }
      let salt = random_bytes(random, sm4_pem_salt_len)
      encrypt_pem_block(key, pwd, salt, iterations)
    }
    LegacyX509 => {
      let iv = random_bytes(random, sm4_pem_key_len)
      encrypt_pem_block_legacy(key, pwd, iv)
    }
  }
}

///|
/// 用指定格式写出加密 PEM（`pwd` 为空时同样写出未加密块）。
/// 兼容旧接口的调用习惯，见 `write_key_to_pem_with`。
pub fn write_key_to_pem_legacy(
  key : SM4Key,
  pwd : Bytes,
  random : @random.Rand?,
) -> String raise SM4Error {
  write_key_to_pem_with(key, pwd, random, Sm4PemEncryption::LegacyX509)
}

///|
/// 用操作系统 CSPRNG（`@env.rand`）播种一个 `@random.Rand`，可直接传给
/// `write_key_to_pem`。平台无 OS 熵源时返回 `None`，此时调用方需自行
/// 提供安全播种的生成器。
///
/// `moonbitlang/core/env` 在 `wasm-gc` 上没有 OS 熵源，此时改用
/// `@sm2.seed_from_entropy` 混合环境中可获得的熵来播种。
pub fn os_rand() -> @random.Rand? {
  let seed = match @env.rand(32) {
    Some(seed) => seed
    None => @sm2.seed_from_entropy()
  }
  Some(@random.Rand::chacha8(seed~))
}

///|
/// 从显式的随机源生成 `n` 字节；`random` 为 `None` 时抛出
/// `MissingRandomSource`。
fn random_bytes(random : @random.Rand?, n : Int32) -> Bytes raise SM4Error {
  let r = match random {
    Some(r) => r
    None => raise SM4Error::MissingRandomSource
  }
  Bytes::makei(n, fn(_) { (r.int(limit=256) & 0xFF).to_byte() })
}

///|
/// 判定 PEM 块是否为加密块，与 Go `x509.IsEncryptedPEMBlock` 一致：
/// 存在 `Proc-Type: 4,ENCRYPTED` 头。
fn is_encrypted_pem_block(block : @byteutil.PemBlock) -> Bool {
  match block.get_header("Proc-Type") {
    Some(v) => v == "4,ENCRYPTED"
    None => false
  }
}

///|
/// 大写十六进制，与 Go 写 DEK-Info 的 IV 一致。
fn hex_upper_string(b : Bytes) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_char(nibble_char((v >> 4) & 0xF))
    sb.write_char(nibble_char(v & 0xF))
  }
  sb.to_string()
}

///|
/// 半字节转大写十六进制字符。
fn nibble_char(n : Int32) -> Char {
  if n < 10 {
    Int32::unsafe_to_char(n + '0'.to_int())
  } else {
    Int32::unsafe_to_char(n - 10 + 'A'.to_int())
  }
}

///|
/// 十六进制字符转数值；非法字符返回 -1。
fn hex_nibble_value(c : UInt16) -> Int32 {
  let v = c.to_int()
  if v >= 0x30 && v <= 0x39 {
    v - 0x30
  } else if v >= 0x41 && v <= 0x46 {
    v - 0x41 + 10
  } else if v >= 0x61 && v <= 0x66 {
    v - 0x61 + 10
  } else {
    -1
  }
}

///|
/// 把 `n` 字节的大写十六进制串解析出来；长度或字符非法时抛
/// `InvalidData`。
fn parse_hex(s : String, n : Int32) -> Bytes raise SM4Error {
  if s.length() != 2 * n {
    raise SM4Error::InvalidData
  }
  Bytes::makei(n, fn(i) raise SM4Error {
    let hi = hex_nibble_value(s[i * 2])
    let lo = hex_nibble_value(s[i * 2 + 1])
    if hi < 0 || lo < 0 {
      raise SM4Error::InvalidData
    }
    ((hi.reinterpret_as_uint() << 4) | lo.reinterpret_as_uint()).to_byte()
  })
}

///|
/// 把 32 个十六进制字符解析成 16 字节（旧格式的 IV）。
fn parse_hex16(s : String) -> Bytes raise SM4Error {
  parse_hex(s, sm4_pem_key_len)
}

///|
/// 把十进制文本解析成非负整数；遇到非法字符或溢出时返回 `None`。
fn parse_decimal(s : String) -> Int32? {
  if s.length() == 0 {
    return None
  }
  let mut v = 0
  for i = 0; i < s.length(); i = i + 1 {
    let d = s[i].to_int() - '0'.to_int()
    if d < 0 || d > 9 {
      return None
    }
    v = v * 10 + d
    if v > sm4_pem_max_iterations {
      return None
    }
  }
  Some(v)
}

///|
/// PKCS#7 填充（分组长度 16 字节，始终追加完整填充）。
fn pkcs7_pad_key(data : Bytes) -> Bytes {
  let n = data.length()
  let pad = sm4_pem_key_len - n % sm4_pem_key_len
  Bytes::makei(n + pad, fn(i) {
    if i < n {
      data[i]
    } else {
      (pad : Int32).to_byte()
    }
  })
}

///|
/// PKCS#7 去填充（分组长度 16 字节）。
///
/// 注意：循环体内不直接 `raise`。当前工具链中，循环内的抛出会破坏
/// 后续的数值比较求值；改为先记录校验结果，循环结束后统一抛出。
fn pkcs7_unpad_key(data : Bytes) -> Bytes raise SM4Error {
  let n = data.length()
  // Check the length *before* touching the last byte: `data[n - 1]` with
  // `n == 0` reads out of bounds.
  if n == 0 || n % sm4_pem_key_len != 0 {
    raise SM4Error::InvalidPadding
  }
  let tail = data[n - 1].to_int()
  let mut ok = true
  ok = ok && tail != 0 && tail <= sm4_pem_key_len
  // 从尾部向前核对 `tail` 个字节，计数到达 tail 即停止。
  let mut checked = 0
  let mut i = n
  while i > 0 && ok {
    i = i - 1
    if checked < tail {
      if data[i].to_int() != tail {
        ok = false
      }
      checked = checked + 1
    }
  }
  if !ok {
    raise SM4Error::InvalidPadding
  }
  Bytes::makei(n - tail, fn(i) { data[i] })
}

///|
/// 由 salt 派生 IV：`HMAC-SM3(K_m, 标签 ‖ salt)[0:16]`。
fn derive_pem_iv(k_m : Bytes, salt : Bytes) -> Bytes {
  let mac = @sm3.hmac_sm3(k_m, @byteutil.concat_bytes([sm4_pem_iv_label, salt]))
  Bytes::makei(sm4_pem_key_len, fn(i) { mac[i] })
}

///|
/// 构造安全格式加密 PEM 块（PBKDF2-HMAC-SM3 → SM4-CBC → HMAC-SM3）。
fn encrypt_pem_block(
  key : Bytes,
  pwd : Bytes,
  salt : Bytes,
  iterations : Int32,
) -> String raise SM4Error {
  let dk = @sm3.pbkdf2_hmac_sm3(pwd, salt, iterations, 64) catch {
    _ => raise SM4Error::InvalidKdfParams
  }
  let k_e = Bytes::makei(sm4_pem_key_len, fn(i) { dk[i] })
  let k_m = Bytes::makei(sm4_pem_key_len, fn(i) { dk[sm4_pem_key_len + i] })
  let iv = derive_pem_iv(k_m, salt)
  let ct = sm4_encrypt_cbc(k_e, iv, pkcs7_pad_key(key))
  let tag = Bytes::makei(sm4_pem_tag_len, fn(i) { @sm3.hmac_sm3(k_m, ct)[i] })
  let headers : @byteutil.Headers = [
    ("Proc-Type", "4,ENCRYPTED"),
    (
      "DEK-Info",
      sm4_pem_cipher_name +
      "," +
      sm4_pem_kdf_name +
      "," +
      hex_upper_string(salt),
    ),
    (sm4_pem_iterations_header, iterations.to_string()),
  ]
  @byteutil.pem_encode(
    sm4_encrypted_key_pem_type,
    headers,
    @byteutil.concat_bytes([ct, tag]),
  )
}

///|
/// 解密安全格式 PEM 块：先常量时间校验 HMAC，再 SM4-CBC 解密、去填充。
fn decrypt_pem_block_pbkdf2(
  block : @byteutil.PemBlock,
  pwd : Bytes,
  salt : Bytes,
  iterations : Int32,
) -> Bytes raise SM4Error {
  let body = block.bytes
  if body.length() < sm4_pem_tag_len || body.length() % sm4_pem_key_len != 0 {
    raise SM4Error::InvalidData
  }
  let ct_len = body.length() - sm4_pem_tag_len
  let ct = Bytes::makei(ct_len, fn(i) { body[i] })
  let tag = Bytes::makei(sm4_pem_tag_len, fn(i) { body[ct_len + i] })
  let dk = @sm3.pbkdf2_hmac_sm3(pwd, salt, iterations, 64) catch {
    _ => raise SM4Error::InvalidKdfParams
  }
  let k_e = Bytes::makei(sm4_pem_key_len, fn(i) { dk[i] })
  let k_m = Bytes::makei(sm4_pem_key_len, fn(i) { dk[sm4_pem_key_len + i] })
  let expected = Bytes::makei(sm4_pem_tag_len, fn(i) {
    @sm3.hmac_sm3(k_m, ct)[i]
  })
  if !@byteutil.ct_eq(expected, tag) {
    raise SM4Error::InvalidTag
  }
  let iv = derive_pem_iv(k_m, salt)
  let padded = sm4_decrypt_cbc(k_e, iv, ct)
  let key = pkcs7_unpad_key(padded)
  if key.length() != sm4_key_size {
    raise SM4Error::InvalidPadding
  }
  key
}

///|
/// 按 `DEK-Info` 分派到安全格式或旧格式的解密流程。
fn decrypt_pem_block(
  block : @byteutil.PemBlock,
  pwd : Bytes,
) -> Bytes raise SM4Error {
  let dek = match block.get_header("DEK-Info") {
    Some(v) => v
    None => raise SM4Error::InvalidData
  }
  let fields = dek.split(",").collect()
  match fields {
    [cipher, kdf, salt_hex] => {
      if cipher != sm4_pem_cipher_name || kdf != sm4_pem_kdf_name {
        raise SM4Error::InvalidData
      }
      let salt = parse_hex(salt_hex.to_owned(), sm4_pem_salt_len)
      let iterations = match block.get_header(sm4_pem_iterations_header) {
        Some(v) =>
          match parse_decimal(v) {
            Some(n) => n
            None => raise SM4Error::InvalidKdfParams
          }
        None => raise SM4Error::InvalidKdfParams
      }
      if iterations < sm4_pem_min_iterations ||
        iterations > sm4_pem_max_iterations {
        raise SM4Error::InvalidKdfParams
      }
      decrypt_pem_block_pbkdf2(block, pwd, salt, iterations)
    }
    [cipher, iv_hex] => {
      if cipher != sm4_pem_legacy_cipher_name {
        raise SM4Error::InvalidData
      }
      let iv = parse_hex16(iv_hex.to_owned())
      decrypt_pem_block_legacy(block, pwd, iv)
    }
    _ => raise SM4Error::InvalidData
  }
}

///|
/// 构造旧格式（RFC 1423 / `x509.EncryptPEMBlock`）加密 PEM 块：口令补零
/// 派生 AES-256 密钥，密钥 PKCS#7 填充后用 CBC 加密。仅用于互通。
fn encrypt_pem_block_legacy(
  key : Bytes,
  pwd : Bytes,
  iv : Bytes,
) -> String raise SM4Error {
  let cipher_key = pem_legacy_key(pwd, 32)
  let padded = pkcs7_pad_key(key)
  let ct = aes256_cbc_encrypt_raw(cipher_key, iv, padded)
  let headers : @byteutil.Headers = [
    ("Proc-Type", "4,ENCRYPTED"),
    ("DEK-Info", sm4_pem_legacy_cipher_name + "," + hex_upper_string(iv)),
  ]
  @byteutil.pem_encode(sm4_encrypted_key_pem_type, headers, ct)
}

///|
/// 解密旧格式 PEM 块：IV 来自 `DEK-Info`，明文按 PKCS#7 去填充以还原密钥。
fn decrypt_pem_block_legacy(
  block : @byteutil.PemBlock,
  pwd : Bytes,
  iv : Bytes,
) -> Bytes raise SM4Error {
  let cipher_key = pem_legacy_key(pwd, 32)
  let padded = aes256_cbc_decrypt_raw(cipher_key, iv, block.bytes)
  let key = pkcs7_unpad_key(padded)
  if key.length() != sm4_key_size {
    raise SM4Error::InvalidPadding
  }
  key
}
