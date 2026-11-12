/// SM4 密钥的 PEM 读写，对齐 gmsm 的 `sm4/utils.go`。
///
/// - `read_key_from_pem` 对应 `ReadKeyFromPem`
/// - `write_key_to_pem` 对应 `WriteKeyToPem`
///
/// 未加密块类型为 `SM4 KEY`，带口令加密时为 `SM4 ENCRYPTED KEY`。
/// 加密格式沿用 Go 旧版 `x509.EncryptPEMBlock` 的 RFC 1423 布局：
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
/// 加密密钥使用的 RFC 1423 算法名。
let sm4_pem_cipher_name : String = "AES-256-CBC"

///|
/// 密钥长度（16 字节）与 AES 分组长度（16 字节）。
let sm4_pem_key_len : Int32 = 16

///|
/// 从 PEM 文本读取 SM4 密钥。加密块需要 `pwd`；未加密块忽略 `pwd`。
/// 对应 `ReadKeyFromPem(data, pwd)`。
///
/// PEM 格式错误、块类型未知、加密块缺少口令、`DEK-Info` 缺失或格式错误
/// 时抛出 `SM4Error::InvalidData`；解密后填充不合法时抛出
/// `SM4Error::InvalidPadding`。
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
/// 把 SM4 密钥编码成 PEM。`pwd` 非空时使用 AES-256-CBC 加密（随机 IV），
/// 块类型为 `SM4 ENCRYPTED KEY`；否则块类型为 `SM4 KEY`。
/// 对应 `WriteKeyToPem(key, pwd)`。
///
/// `random` 用于生成加密 IV，加密时必须提供安全播种的生成器；
/// 传 `None` 会直接 abort（不再有共享的固定种子兜底）。
/// `pwd` 为空时不产生随机数，可传 `None`。
pub fn write_key_to_pem(
  key : SM4Key,
  pwd : Bytes,
  random : @random.Rand?,
) -> String raise SM4Error {
  if key.length() != sm4_key_size {
    raise SM4Error::InvalidKey
  }
  if pwd.length() == 0 {
    @byteutil.pem_encode_simple(sm4_key_pem_type, key)
  } else {
    let r = match random {
      Some(r) => r
      None => raise SM4Error::MissingRandomSource
    }
    let iv = Bytes::makei(sm4_pem_key_len, fn(_) {
      (r.int(limit=256) & 0xFF).to_byte()
    })
    encrypt_pem_block(key, pwd, iv)
  }
}

///|
/// 用操作系统 CSPRNG（`@env.rand`）播种一个 `@random.Rand`，可直接传给
/// `write_key_to_pem`。平台无 OS 熵源（如 `wasm`）时返回 `None`，
/// 此时调用方需自行提供安全播种的生成器。
pub fn os_rand() -> @random.Rand? {
  match @env.rand(32) {
    Some(seed) => Some(@random.Rand::chacha8(seed~))
    None => None
  }
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
/// 把 32 个十六进制字符解析成 16 字节。
fn parse_hex16(s : String) -> Bytes raise SM4Error {
  if s.length() != 2 * sm4_pem_key_len {
    raise SM4Error::InvalidData
  }
  let out = Bytes::makei(sm4_pem_key_len, fn(i) raise SM4Error {
    let hi = hex_nibble_value(s[i * 2])
    let lo = hex_nibble_value(s[i * 2 + 1])
    if hi < 0 || lo < 0 {
      raise SM4Error::InvalidData
    }
    ((hi.reinterpret_as_uint() << 4) | lo.reinterpret_as_uint()).to_byte()
  })
  out
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
  let tail = data[n - 1].to_int()
  let mut ok = n != 0 && n % sm4_pem_key_len == 0
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
/// 构造加密 PEM 块：口令补零派生 AES-256 密钥，密钥 PKCS#7 填充后用 CBC
/// 加密，并写入 RFC 1423 头部。
fn encrypt_pem_block(
  key : Bytes,
  pwd : Bytes,
  iv : Bytes,
) -> String raise SM4Error {
  let cipher_key = pem_legacy_key(pwd, 32)
  let padded = pkcs7_pad_key(key)
  let ct = aes256_cbc_encrypt_raw(cipher_key, iv, padded)
  let headers : @byteutil.Headers = [
    ("Proc-Type", "4,ENCRYPTED"),
    ("DEK-Info", sm4_pem_cipher_name + "," + hex_upper_string(iv)),
  ]
  @byteutil.pem_encode(sm4_encrypted_key_pem_type, headers, ct)
}

///|
/// 解密加密 PEM 块：IV 来自 `DEK-Info`，明文按 PKCS#7 去填充以还原密钥。
fn decrypt_pem_block(
  block : @byteutil.PemBlock,
  pwd : Bytes,
) -> Bytes raise SM4Error {
  let dek = match block.get_header("DEK-Info") {
    Some(v) => v
    None => raise SM4Error::InvalidData
  }
  let comma = match dek.find(",") {
    Some(i) => i
    None => raise SM4Error::InvalidData
  }
  let cipher_name = dek[0:comma].to_owned()
  if cipher_name != sm4_pem_cipher_name {
    raise SM4Error::InvalidData
  }
  let iv = parse_hex16(dek[comma + 1:].to_owned())
  let cipher_key = pem_legacy_key(pwd, 32)
  let padded = aes256_cbc_decrypt_raw(cipher_key, iv, block.bytes)
  let key = pkcs7_unpad_key(padded)
  if key.length() != sm4_key_size {
    raise SM4Error::InvalidPadding
  }
  key
}
