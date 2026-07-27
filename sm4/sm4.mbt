/// SM4 block cipher (GM/T 0002-2012).
///
/// SM4 is a Feistel-based block cipher with:
/// - Block size: 128-bit (16 bytes)
/// - Key size: 128-bit (16 bytes)
/// - Rounds: 32

///|
/// SM4 S-Box (256-byte fixed substitution table, from GM/T 0002-2012).
let SBOX : FixedArray[Byte] = [
  b'\xd6', b'\x90', b'\xe9', b'\xfe', b'\xcc', b'\xe1', b'\x3d', b'\xb7',
  b'\x16', b'\xb6', b'\x14', b'\xc2', b'\x28', b'\xfb', b'\x2c', b'\x05',
  b'\x2b', b'\x67', b'\x9a', b'\x76', b'\x2a', b'\xbe', b'\x04', b'\xc3',
  b'\xaa', b'\x44', b'\x13', b'\x26', b'\x49', b'\x86', b'\x06', b'\x99',
  b'\x9c', b'\x42', b'\x50', b'\xf4', b'\x91', b'\xef', b'\x98', b'\x7a',
  b'\x33', b'\x54', b'\x0b', b'\x43', b'\xed', b'\xcf', b'\xac', b'\x62',
  b'\xe4', b'\xb3', b'\x1c', b'\xa9', b'\xc9', b'\x08', b'\xe8', b'\x95',
  b'\x80', b'\xdf', b'\x94', b'\xfa', b'\x75', b'\x8f', b'\x3f', b'\xa6',
  b'\x47', b'\x07', b'\xa7', b'\xfc', b'\xf3', b'\x73', b'\x17', b'\xba',
  b'\x83', b'\x59', b'\x3c', b'\x19', b'\xe6', b'\x85', b'\x4f', b'\xa8',
  b'\x68', b'\x6b', b'\x81', b'\xb2', b'\x71', b'\x64', b'\xda', b'\x8b',
  b'\xf8', b'\xeb', b'\x0f', b'\x4b', b'\x70', b'\x56', b'\x9d', b'\x35',
  b'\x1e', b'\x24', b'\x0e', b'\x5e', b'\x63', b'\x58', b'\xd1', b'\xa2',
  b'\x25', b'\x22', b'\x7c', b'\x3b', b'\x01', b'\x21', b'\x78', b'\x87',
  b'\xd4', b'\x00', b'\x46', b'\x57', b'\x9f', b'\xd3', b'\x27', b'\x52',
  b'\x4c', b'\x36', b'\x02', b'\xe7', b'\xa0', b'\xc4', b'\xc8', b'\x9e',
  b'\xea', b'\xbf', b'\x8a', b'\xd2', b'\x40', b'\xc7', b'\x38', b'\xb5',
  b'\xa3', b'\xf7', b'\xf2', b'\xce', b'\xf9', b'\x61', b'\x15', b'\xa1',
  b'\xe0', b'\xae', b'\x5d', b'\xa4', b'\x9b', b'\x34', b'\x1a', b'\x55',
  b'\xad', b'\x93', b'\x32', b'\x30', b'\xf5', b'\x8c', b'\xb1', b'\xe3',
  b'\x1d', b'\xf6', b'\xe2', b'\x2e', b'\x82', b'\x66', b'\xca', b'\x60',
  b'\xc0', b'\x29', b'\x23', b'\xab', b'\x0d', b'\x53', b'\x4e', b'\x6f',
  b'\xd5', b'\xdb', b'\x37', b'\x45', b'\xde', b'\xfd', b'\x8e', b'\x2f',
  b'\x03', b'\xff', b'\x6a', b'\x72', b'\x6d', b'\x6c', b'\x5b', b'\x51',
  b'\x8d', b'\x1b', b'\xaf', b'\x92', b'\xbb', b'\xdd', b'\xbc', b'\x7f',
  b'\x11', b'\xd9', b'\x5c', b'\x41', b'\x1f', b'\x10', b'\x5a', b'\xd8',
  b'\x0a', b'\xc1', b'\x31', b'\x88', b'\xa5', b'\xcd', b'\x7b', b'\xbd',
  b'\x2d', b'\x74', b'\xd0', b'\x12', b'\xb8', b'\xe5', b'\xb4', b'\xb0',
  b'\x89', b'\x69', b'\x97', b'\x4a', b'\x0c', b'\x96', b'\x77', b'\x7e',
  b'\x65', b'\xb9', b'\xf1', b'\x09', b'\xc5', b'\x6e', b'\xc6', b'\x84',
  b'\x18', b'\xf0', b'\x7d', b'\xec', b'\x3a', b'\xdc', b'\x4d', b'\x20',
  b'\x79', b'\xee', b'\x5f', b'\x3e', b'\xd7', b'\xcb', b'\x39', b'\x48',
]

///|
/// System parameters FK (GM/T 0002-2012 Appendix A.1).
let FK : FixedArray[UInt] = [
  0xA3B1BAC6U, 0x56AA3350U, 0x677D9197U, 0xB27022DCU,
]

///|
/// Fixed parameters CK (GM/T 0002-2012 Appendix A.2).
/// CK[i][j] = (4i + j) × 7 mod 256
let CK : FixedArray[UInt] = FixedArray::makei(32, fn(i) {
  let base = (i * 4).to_uint()
  ((base * 7U) & 0xFFU) << 24 |
  (((base + 1U) * 7U) & 0xFFU) << 16 |
  (((base + 2U) * 7U) & 0xFFU) << 8 |
  ((base + 3U) * 7U) & 0xFFU
})

///|
pub suberror SM4Error {
  InvalidKey       // key length != 16 bytes
  InvalidData      // data length not a multiple of 16
  InvalidIV        // IV not empty and length != 16 bytes
  InvalidPadding   // PKCS7 unpadding: padding value invalid
  DecryptFailed    // CBC decrypt failed
} derive(Show, Eq)

///|
/// 32-bit left rotation.
fn rotl(x : UInt, n : Int) -> UInt {
  let n = n % 32
  (x << n) | (x >> (32 - n))
}

///|
/// Read a 32-bit unsigned integer from `buf` at `offset` in big-endian byte order.
fn get_u32_be(buf : Bytes, offset : Int) -> UInt {
  (buf[offset].to_uint() << 24) |
  (buf[offset + 1].to_uint() << 16) |
  (buf[offset + 2].to_uint() << 8) |
  buf[offset + 3].to_uint()
}

///|
/// Write a 32-bit unsigned integer `v` to `buf` at `offset` in big-endian byte order.
fn put_u32_be(buf : Bytes, offset : Int, v : UInt) -> Unit {
  buf[offset] = (v >> 24).to_byte()
  buf[offset + 1] = ((v >> 16) & 0xFFU).to_byte()
  buf[offset + 2] = ((v >> 8) & 0xFFU).to_byte()
  buf[offset + 3] = (v & 0xFFU).to_byte()
}

///|
/// Non-linear transformation τ: substitute each byte via S-Box.
fn sm4_tau(a : UInt) -> UInt {
  let a0 = ((a >> 24) & 0xFFU).to_int()
  let a1 = ((a >> 16) & 0xFFU).to_int()
  let a2 = ((a >> 8) & 0xFFU).to_int()
  let a3 = (a & 0xFFU).to_int()
  (SBOX[a0].to_uint() << 24) | (SBOX[a1].to_uint() << 16) | (SBOX[a2].to_uint() << 8) | SBOX[a3].to_uint()
}

///|
/// Linear transformation L (used in round function).
fn sm4_L(b : UInt) -> UInt {
  b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
}

///|
/// Linear transformation L' (used in key expansion).
fn sm4_L_prime(b : UInt) -> UInt {
  b ^ rotl(b, 13) ^ rotl(b, 23)
}

///|
/// Round function F: F(X0, X1, X2, X3, rk) = X0 ⊕ T(X1 ⊕ X2 ⊕ X3 ⊕ rk)
fn sm4_F(x0 : UInt, x1 : UInt, x2 : UInt, x3 : UInt, rk : UInt) -> UInt {
  x0 ^ sm4_L(sm4_tau(x1 ^ x2 ^ x3 ^ rk))
}

///|
/// T' used in key expansion: T'(.) = L'(τ(.))
fn sm4_T_prime(a : UInt) -> UInt {
  sm4_L_prime(sm4_tau(a))
}

///|
/// Key expansion: derive 32 round keys from 16-byte key.
/// Returns round keys in encryption order.
fn sm4_expand_key(key : Bytes) -> FixedArray[UInt] {
  if key.length() != 16 {
    abort("SM4Error::InvalidKey")
  }

  let mk : FixedArray[UInt] = FixedArray::makei(4, fn(i) {
    get_u32_be(key, i * 4)
  })

  // K[0..3] = MK[i] ⊕ FK[i]
  let mut k : FixedArray[UInt] = FixedArray::makei(36, fn(i) {
    if i < 4 { mk[i] ^ FK[i] } else { 0U }
  })

  // rk[0..31]
  let rk : FixedArray[UInt] = FixedArray::makei(32, fn(_i) { 0U })

  for i = 0; i < 32; i = i + 1 {
    k[i + 4] = k[i] ^ sm4_T_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i])
    rk[i] = k[i + 4]
  }

  rk
}

///|
/// Process one 128-bit block through SM4 with the given round keys.
fn sm4_process_block(x : FixedArray[UInt], rk : FixedArray[UInt]) -> FixedArray[UInt] {
  let n = 4
  let mut xv : FixedArray[UInt] = FixedArray::makei(36, fn(i) {
    if i < n { x[i] } else { 0U }
  })

  for i = 0; i < 32; i = i + 1 {
    xv[i + n] = sm4_F(xv[i], xv[i + 1], xv[i + 2], xv[i + 3], rk[i])
  }

  FixedArray::makei(4, fn(i) { xv[35 - i] })
}

///|
/// Single block encryption: key and data must each be 16 bytes.
/// Returns 16-byte ciphertext.
pub fn sm4_encrypt_block(key : Bytes, data : Bytes) -> Bytes {
  if key.length() != 16 { abort("SM4Error::InvalidKey") }
  if data.length() != 16 { abort("SM4Error::InvalidData") }

  let rk = sm4_expand_key(key)
  let x : FixedArray[UInt] = FixedArray::makei(4, fn(i) {
    get_u32_be(data, i * 4)
  })

  let y = sm4_process_block(x, rk)
  Bytes::makei(16, fn(i) {
    let word = y[i / 4]
    let shift = 24 - (i % 4) * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// Single block decryption: key and data must each be 16 bytes.
/// Returns 16-byte plaintext.
pub fn sm4_decrypt_block(key : Bytes, data : Bytes) -> Bytes {
  if key.length() != 16 { abort("SM4Error::InvalidKey") }
  if data.length() != 16 { abort("SM4Error::InvalidData") }

  let rk = sm4_expand_key(key)

  // Reverse round keys for decryption
  let rk_rev : FixedArray[UInt] = FixedArray::makei(32, fn(i) { rk[31 - i] })

  let x : FixedArray[UInt] = FixedArray::makei(4, fn(i) {
    get_u32_be(data, i * 4)
  })

  let y = sm4_process_block(x, rk_rev)
  Bytes::makei(16, fn(i) {
    let word = y[i / 4]
    let shift = 24 - (i % 4) * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// ECB mode encryption: data length must be a multiple of 16.
pub fn sm4_encrypt_ecb(key : Bytes, data : Bytes) -> Bytes {
  if key.length() != 16 { abort("SM4Error::InvalidKey") }
  if data.length() % 16 != 0 { abort("SM4Error::InvalidData") }

  let rk = sm4_expand_key(key)
  let n_blocks = data.length() / 16
  // Pre-compute all result blocks as flat array of 32-bit words
  let mut result_words : FixedArray[UInt] = FixedArray::makei(n_blocks * 4, fn(_i) { 0U })
  for b = 0; b < n_blocks; b = b + 1 {
    let x : FixedArray[UInt] = FixedArray::makei(4, fn(j) {
      get_u32_be(data, b * 16 + j * 4)
    })
    let encrypted = sm4_process_block(x, rk)
    for j = 0; j < 4; j = j + 1 {
      result_words[b * 4 + j] = encrypted[j]
    }
  }
  Bytes::makei(data.length(), fn(i) {
    let word_idx = i / 4
    let word = result_words[word_idx]
    let shift = 24 - (i % 4) * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// ECB mode decryption: data length must be a multiple of 16.
pub fn sm4_decrypt_ecb(key : Bytes, data : Bytes) -> Bytes {
  if key.length() != 16 { abort("SM4Error::InvalidKey") }
  if data.length() % 16 != 0 { abort("SM4Error::InvalidData") }

  let rk = sm4_expand_key(key)
  let rk_rev : FixedArray[UInt] = FixedArray::makei(32, fn(i) { rk[31 - i] })
  let n_blocks = data.length() / 16
  let mut result_words : FixedArray[UInt] = FixedArray::makei(n_blocks * 4, fn(_i) { 0U })
  for b = 0; b < n_blocks; b = b + 1 {
    let x : FixedArray[UInt] = FixedArray::makei(4, fn(j) {
      get_u32_be(data, b * 16 + j * 4)
    })
    let decrypted = sm4_process_block(x, rk_rev)
    for j = 0; j < 4; j = j + 1 {
      result_words[b * 4 + j] = decrypted[j]
    }
  }
  Bytes::makei(data.length(), fn(i) {
    let word_idx = i / 4
    let word = result_words[word_idx]
    let shift = 24 - (i % 4) * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// CBC mode encryption. IV must be 16 bytes.
pub fn sm4_encrypt_cbc(key : Bytes, iv : Bytes, data : Bytes) -> Bytes {
  if key.length() != 16 { abort("SM4Error::InvalidKey") }
  if iv.length() != 16 { abort("SM4Error::InvalidIV") }
  if data.length() % 16 != 0 { abort("SM4Error::InvalidData") }

  let rk = sm4_expand_key(key)
  let n_blocks = data.length() / 16
  let mut result_words : FixedArray[UInt] = FixedArray::makei(n_blocks * 4, fn(_i) { 0U })
  for b = 0; b < n_blocks; b = b + 1 {
    // Compute plaintext block
    let plain : FixedArray[UInt] = FixedArray::makei(4, fn(j) {
      get_u32_be(data, b * 16 + j * 4)
    })
    // Previous ciphertext (or IV for block 0)
    let prev : FixedArray[UInt] = if b == 0 {
      FixedArray::makei(4, fn(j) { get_u32_be(iv, j * 4) })
    } else {
      FixedArray::makei(4, fn(j) { result_words[(b - 1) * 4 + j] })
    }
    // XOR and encrypt
    let xored : FixedArray[UInt] = FixedArray::makei(4, fn(j) { plain[j] ^ prev[j] })
    let encrypted = sm4_process_block(xored, rk)
    for j = 0; j < 4; j = j + 1 {
      result_words[b * 4 + j] = encrypted[j]
    }
  }
  Bytes::makei(data.length(), fn(i) {
    let word_idx = i / 4
    let word = result_words[word_idx]
    let shift = 24 - (i % 4) * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// CBC mode decryption. IV must be 16 bytes. Data length must be a multiple of 16.
pub fn sm4_decrypt_cbc(key : Bytes, iv : Bytes, data : Bytes) -> Bytes {
  if key.length() != 16 { abort("SM4Error::InvalidKey") }
  if iv.length() != 16 { abort("SM4Error::InvalidIV") }
  if data.length() % 16 != 0 { abort("SM4Error::InvalidData") }

  let rk = sm4_expand_key(key)
  let rk_rev : FixedArray[UInt] = FixedArray::makei(32, fn(i) { rk[31 - i] })
  let n_blocks = data.length() / 16
  let mut result_words : FixedArray[UInt] = FixedArray::makei(n_blocks * 4, fn(_i) { 0U })
  for b = 0; b < n_blocks; b = b + 1 {
    // Decrypt ciphertext block
    let cipher : FixedArray[UInt] = FixedArray::makei(4, fn(j) {
      get_u32_be(data, b * 16 + j * 4)
    })
    let decrypted = sm4_process_block(cipher, rk_rev)
    // Previous ciphertext (or IV for block 0)
    let prev : FixedArray[UInt] = if b == 0 {
      FixedArray::makei(4, fn(j) { get_u32_be(iv, j * 4) })
    } else {
      FixedArray::makei(4, fn(j) { get_u32_be(data, (b - 1) * 16 + j * 4) })
    }
    // XOR to get plaintext
    for j = 0; j < 4; j = j + 1 {
      result_words[b * 4 + j] = decrypted[j] ^ prev[j]
    }
  }
  Bytes::makei(data.length(), fn(i) {
    let word_idx = i / 4
    let word = result_words[word_idx]
    let shift = 24 - (i % 4) * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// PKCS7 padding.
pub fn pkcs7_pad(data : Bytes, block_size : Int) -> Bytes {
  let pad_len = block_size - data.length() % block_size
  let pad_byte = pad_len.to_byte()
  Bytes::makei(data.length() + pad_len, fn(i) {
    if i < data.length() { data[i] } else { pad_byte }
  })
}

///|
/// PKCS7 unpadding. Removes the padding and returns the original data.
pub fn pkcs7_unpad(data : Bytes) -> Bytes {
  if data.length() == 0 { abort("SM4Error::InvalidPadding") }
  let pad_len = data[data.length() - 1].to_int()
  if pad_len < 1 || pad_len > 16 { abort("SM4Error::InvalidPadding") }
  if pad_len > data.length() { abort("SM4Error::InvalidPadding") }

  // Verify all padding bytes are correct
  for i = data.length() - pad_len; i < data.length(); i = i + 1 {
    if data[i].to_int() != pad_len { abort("SM4Error::InvalidPadding") }
  }

  data[0:data.length() - pad_len].to_owned()
}
