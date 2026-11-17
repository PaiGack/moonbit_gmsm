/// SM4 密钥的 PEM 读写，对齐 gmsm 的 `sm4/utils.go`，并在其基础上加强
/// 口令加密的密钥派生。
///
/// - `read_key_from_pem` 对应 `ReadKeyFromPem`
/// - `write_key_to_pem` 对应 `WriteKeyToPem`
///
/// 未加密块类型为 `SM4 KEY`。带口令加密时，默认写出安全的
/// `SM4 ENCRYPTED KEY`（PBKDF2-HMAC-SM3 + SM4-CBC + HMAC-SM3 认证）；
/// 需要与 Go `x509.EncryptPEMBlock` / gmsm 互通时，可用
/// `write_key_to_pem_legacy` 显式写出旧格式，读取端始终兼容旧格式；只想读
/// 旧格式并防止头部降级时用 `read_key_from_pem_legacy`。
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
  /// 读取端见 `read_key_from_pem_legacy`。
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
/// 读取端接受的 PEM 密钥加密格式。
///
/// `read_key_from_pem` 默认全部接受（与 gmsm 兼容）；需要判定密钥来源可信时
/// 改用 `read_key_from_pem_strict`，只接受本库写出的安全格式。
pub(all) enum Sm4PemReadPolicy {
  /// 明文 `SM4 KEY`、安全格式、旧格式（`AES-256-CBC`）都接受。
  /// 只负责解码，**不保证来源可信**。
  AcceptAny
  /// 只接受安全格式（PBKDF2-HMAC-SM3 + SM4-CBC + HMAC-SM3）。明文块与
  /// 旧格式一律拒绝，不存在静默降级。
  EncryptedOnly
}

///|
/// 从 PEM 文本读取 SM4 密钥。加密块需要 `pwd`；未加密块忽略 `pwd`。
/// 对应 `ReadKeyFromPem(data, pwd)`。
///
/// **本函数只负责解码，不保证来源可信**：未加密块（`SM4 KEY`）里就是明文
/// 密钥，传了 `pwd` 也**不会**解密；加密块也会按 `DEK-Info` 自动降级到无
/// 认证的旧格式（`AES-256-CBC,...`）。任何能改写文件的人都可以把密文换成
/// 自己指定的明文密钥，或把头部改成旧格式来绕过认证。需要在安全边界上
/// 导入密钥时请用 `read_key_from_pem_strict`：
///
/// ```mbt nocheck
/// let key = read_key_from_pem_strict(data, pwd, Sm4PemReadPolicy::EncryptedOnly)
/// ```
///
/// 加密块会按 `DEK-Info` 自动识别安全格式（`SM4-CBC,PBKDF2-HMAC-SM3,...`）
/// 或旧格式（`AES-256-CBC,...`）并解密；读取旧格式时不受时间攻击保护，
/// 应在迁移后重新用 `write_key_to_pem` 写出。只想读旧格式时用
/// `read_key_from_pem_legacy`，它会拒绝安全的与明文的块。
///
/// 错误语义见 `read_key_from_pem_strict`；旧格式解密失败抛
/// `SM4Error::LegacyPemDecryptFailed`（不区分口令错误与填充错误）。
pub fn read_key_from_pem(data : String, pwd : Bytes) -> SM4Key raise SM4Error {
  read_key_from_pem_strict(data, pwd, Sm4PemReadPolicy::AcceptAny)
}

///|
/// **仅供导入旧文件**：只读取旧格式（`AES-256-CBC`）加密的 PEM 块，用于把
/// Go `x509.EncryptPEMBlock` / gmsm 写出的密钥迁移进本库。**导入后应立即用
/// `write_key_to_pem` 以安全格式重写**，不要长期持有或继续分发旧格式文件。
///
/// 旧格式无盐、无迭代、无 MAC：拿到文件的人可以低成本暴力破解口令，密文也
/// 不可认证。读取端的防护只有下面两条：
///
/// - **不接受头部降级**：块类型必须是 `SM4 ENCRYPTED KEY`，`Proc-Type` 必须
///   是 `4,ENCRYPTED`，`DEK-Info` 必须恰为两字段的 `AES-256-CBC,<16 字节 IV
///   十六进制>`，且不得携带安全格式的 `SM4-KDF-Iterations` 头。安全格式、
///   明文 `SM4 KEY` 都会 `raise SM4Error::InvalidData`。
/// - **错误不可区分**：口令错误、密文损坏、填充不合法统一抛
///   `SM4Error::LegacyPemDecryptFailed`；去填充为常量时间实现，避免把这条
///   无认证路径变成 padding oracle。
///
/// 口令长度语义与 Go 一致：不足 32 字节补零，超过 32 字节**截断**到 32 字节
/// （`x509.EncryptPEMBlock` 的 `copy` 语义），因此长口令文件也能互通。
///
/// ```mbt nocheck
/// let key = read_key_from_pem_legacy(old_pem, pwd)
///
/// let migrated = write_key_to_pem(key, pwd, os_rand())
/// ```
pub fn read_key_from_pem_legacy(
  data : String,
  pwd : Bytes,
) -> SM4Key raise SM4Error {
  let block = @byteutil.pem_decode(data) catch {
    _ => raise SM4Error::InvalidData
  }
  if !is_encrypted_pem_block(block) || block.type_ != sm4_encrypted_key_pem_type {
    raise SM4Error::InvalidData
  }
  if pwd.length() == 0 || block.get_header(sm4_pem_iterations_header) != None {
    raise SM4Error::InvalidData
  }
  let fields = match block.get_header("DEK-Info") {
    Some(v) => v.split(",").collect()
    None => raise SM4Error::InvalidData
  }
  match fields {
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
/// 按 `policy` 读取 PEM 密钥，用于需要**认证来源**的场景。
///
/// - `AcceptAny`：与 `read_key_from_pem` 完全相同，接受明文块、安全格式与
///   旧格式。
/// - `EncryptedOnly`：认证密钥导入的推荐入口。要求块类型为
///   `SM4 ENCRYPTED KEY`、`Proc-Type: 4,ENCRYPTED`、`DEK-Info` 恰好是安全
///   格式，并强制 `pwd` 非空。明文块、旧格式（包括把安全格式的 `DEK-Info`
///   改成 `AES-256-CBC,...` 的降级）都不接受。
///
/// 无论哪种策略，安全格式本身都以 `c ‖ tag` 的 HMAC-SM3 认证为准——头部
/// 字段（块类型、`Proc-Type`、`DEK-Info` 的参数）不参与认证，所以只要还
/// 接受旧格式或明文，就不能把「读取成功」当成「文件未被篡改」。反过来，
/// 在 `EncryptedOnly` 下改任何一项头部都会导致读取失败：参数不在白名单里，
/// 或密文不再能通过 MAC。
///
/// PEM 格式错误、块类型未知、加密块缺少口令、`DEK-Info` 缺失或格式错误，
/// 以及 `EncryptedOnly` 下遇到明文块 / 旧格式时，抛出
/// `SM4Error::InvalidData`；解密后填充不合法时抛出
/// `SM4Error::InvalidPadding`；安全格式的认证标签不匹配时抛出
/// `SM4Error::InvalidTag`；KDF 参数越界（如迭代次数过大）时抛出
/// `SM4Error::InvalidKdfParams`。
pub fn read_key_from_pem_strict(
  data : String,
  pwd : Bytes,
  policy : Sm4PemReadPolicy,
) -> SM4Key raise SM4Error {
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
    decrypt_pem_block(block, pwd, policy)
  } else {
    if policy == Sm4PemReadPolicy::EncryptedOnly {
      raise SM4Error::InvalidData
    }
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
/// 新代码应使用 `write_key_to_pem`。口令语义与 Go 一致：不足 32 字节补零、
/// 超过 32 字节截断到 32 字节。
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
/// 用旧格式（`x509.EncryptPEMBlock` 兼容）写出加密 PEM（`pwd` 为空时同样写出
/// 未加密块）。兼容旧接口的调用习惯，见 `write_key_to_pem_with`。
///
/// **仅为互通保留**：旧格式无盐、无迭代、无 MAC。读取端对应
/// `read_key_from_pem_legacy`；迁移到安全格式时用 `write_key_to_pem` 重写。
pub fn write_key_to_pem_legacy(
  key : SM4Key,
  pwd : Bytes,
  random : @random.Rand?,
) -> String raise SM4Error {
  write_key_to_pem_with(key, pwd, random, Sm4PemEncryption::LegacyX509)
}

///|
/// 用操作系统 CSPRNG（`@env.rand`）播种一个 `@random.Rand`，可直接传给
/// `write_key_to_pem`。
///
/// 平台无 OS 熵源时（例如 `wasm-gc`，`@env.rand` 恒报失败）退化为
/// `@sm2.seed_from_entropy()` 播种，并先向 stderr 打印告警：该来源在完全
/// 隔离的主机上只剩时钟与调用计数器，**不是密码学安全的**。
pub fn os_rand() -> @random.Rand? {
  let seed = match @env.rand(32) {
    Some(seed) => seed
    None => {
      eprintln(
        "[gmsm] WARNING: no OS entropy source available; falling back to seed_from_entropy() (clock + call counter). PEM keys/IVs generated with this source are NOT cryptographically secure.",
      )
      @sm2.seed_from_entropy()
    }
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
/// 常量时间的 PKCS#7 去填充（分组长度 16 字节），只供无认证的**旧格式**
/// PEM 解密使用——这条路径没有 MAC，填充校验是攻击者唯一能观察到的差异，
/// 因此这里不提前返回、不按 `tail` 变化循环次数：
///
/// - 16 个尾部字节逐个与 `tail` 比较，差异 OR 进同一个累加器；
/// - 每个字节都用同一张「保留掩码」做与运算，输出长度恒为 `n - 16`，
///   合法与非法填充走完全相同的路径；
/// - 填充是否合法只以单个 `Bool` 返回，调用方随后统一抛
///   `SM4Error::LegacyPemDecryptFailed`，不区分「口令错误」与「填充错误」。
///
/// 同时校验 `tail != 0`、`tail <= 16`。
fn pkcs7_unpad_key_ct(data : Bytes) -> (Bytes, Bool) {
  let n = data.length()
  if n < sm4_pem_key_len || n % sm4_pem_key_len != 0 {
    return (b"", false)
  }
  let tail = data[n - 1].to_uint()
  let mut tail_ok = tail != 0U && tail <= sm4_pem_key_len.reinterpret_as_uint()
  // 位置 `j`（从末尾数，0 起）是否属于填充：不属于时为 `0xFF` 保留、
  // 属于时为 `0x00` 清零的掩码。
  let keep_mask = fn(j : Int32) -> Int32 {
    let d = j - tail.reinterpret_as_int() + 1
    // `d <= 0` → 0x00（属于填充）；`d > 0` → 0xFF（保留）。
    (d >> 31) & 0xFF
  }
  let mut diff : UInt32 = 0U
  for j = 0; j < sm4_pem_key_len; j = j + 1 {
    let m = keep_mask(j)
    // 属于填充区的字节必须等于 tail；保留区不参与判断。
    let neq = data[n - 1 - j].to_uint() ^ tail
    let nonzero = (neq | (0U - neq)) >> 31
    diff = diff | (nonzero & (m ^ 0xFF).reinterpret_as_uint())
  }
  tail_ok = tail_ok && diff == 0U
  let keep = n - sm4_pem_key_len
  let out = Bytes::makei(keep, fn(i) {
    (data[i].to_int() & keep_mask(i - (keep - 1))).to_byte()
  })
  (out, tail_ok)
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
#deprecated
pub extend Sm4PemReadPolicy with Eq::{not_equal, equal}

///|
pub impl Eq for Sm4PemReadPolicy with fn equal(self, other) {
  match (self, other) {
    (AcceptAny, AcceptAny) | (EncryptedOnly, EncryptedOnly) => true
    _ => false
  }
}

///|
/// 按 `DEK-Info` 分派到安全格式或旧格式的解密流程。`policy` 为
/// `EncryptedOnly` 时旧格式被拒绝，不会降级。
fn decrypt_pem_block(
  block : @byteutil.PemBlock,
  pwd : Bytes,
  policy : Sm4PemReadPolicy,
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
      if cipher != sm4_pem_legacy_cipher_name ||
        policy == Sm4PemReadPolicy::EncryptedOnly {
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
/// 旧格式解密的核心：只负责「无认证的 CBC 解密 + 常量时间去填充」，不检查
/// 块类型、不检查读取策略。`read_key_from_pem_*` 与
/// `read_key_from_pem_legacy` 都经由它，旧格式的参数校验只有这一份实现。
///
/// 解密失败（口令错误、密文被改成非 16 字节倍数、填充不合法、去填充后不是
/// 16 字节）一律抛 `SM4Error::LegacyPemDecryptFailed`，**不区分具体原因**：
/// 旧格式没有 MAC，把「填充错误」和「口令错误」分开报告就是一个 padding
/// oracle。填充检查本身走 `pkcs7_unpad_key_ct`，不提前返回。
fn decrypt_pem_block_legacy(
  block : @byteutil.PemBlock,
  pwd : Bytes,
  iv : Bytes,
) -> Bytes raise SM4Error {
  let cipher_key = pem_legacy_key(pwd, 32)
  let padded = aes256_cbc_decrypt_raw(cipher_key, iv, block.bytes) catch {
    _ => raise SM4Error::LegacyPemDecryptFailed
  }
  let (key, ok) = pkcs7_unpad_key_ct(padded)
  if !ok || key.length() != sm4_key_size {
    raise SM4Error::LegacyPemDecryptFailed
  }
  key
}
