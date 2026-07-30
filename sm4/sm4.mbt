/// SM4 block cipher (GM/T 0002-2012).
///
/// SM4 is a Feistel-based block cipher with:
/// - Block size: 128-bit (16 bytes)
/// - Key size: 128-bit (16 bytes)
/// - Rounds: 32

///|
/// SM4 S-Box (256-byte fixed substitution table, from GM/T 0002-2012).
let sbox : FixedArray[Byte] = [
  b'\xd6', b'\x90', b'\xe9', b'\xfe', b'\xcc', b'\xe1', b'\x3d', b'\xb7', b'\x16',
  b'\xb6', b'\x14', b'\xc2', b'\x28', b'\xfb', b'\x2c', b'\x05', b'\x2b', b'\x67',
  b'\x9a', b'\x76', b'\x2a', b'\xbe', b'\x04', b'\xc3', b'\xaa', b'\x44', b'\x13',
  b'\x26', b'\x49', b'\x86', b'\x06', b'\x99', b'\x9c', b'\x42', b'\x50', b'\xf4',
  b'\x91', b'\xef', b'\x98', b'\x7a', b'\x33', b'\x54', b'\x0b', b'\x43', b'\xed',
  b'\xcf', b'\xac', b'\x62', b'\xe4', b'\xb3', b'\x1c', b'\xa9', b'\xc9', b'\x08',
  b'\xe8', b'\x95', b'\x80', b'\xdf', b'\x94', b'\xfa', b'\x75', b'\x8f', b'\x3f',
  b'\xa6', b'\x47', b'\x07', b'\xa7', b'\xfc', b'\xf3', b'\x73', b'\x17', b'\xba',
  b'\x83', b'\x59', b'\x3c', b'\x19', b'\xe6', b'\x85', b'\x4f', b'\xa8', b'\x68',
  b'\x6b', b'\x81', b'\xb2', b'\x71', b'\x64', b'\xda', b'\x8b', b'\xf8', b'\xeb',
  b'\x0f', b'\x4b', b'\x70', b'\x56', b'\x9d', b'\x35', b'\x1e', b'\x24', b'\x0e',
  b'\x5e', b'\x63', b'\x58', b'\xd1', b'\xa2', b'\x25', b'\x22', b'\x7c', b'\x3b',
  b'\x01', b'\x21', b'\x78', b'\x87', b'\xd4', b'\x00', b'\x46', b'\x57', b'\x9f',
  b'\xd3', b'\x27', b'\x52', b'\x4c', b'\x36', b'\x02', b'\xe7', b'\xa0', b'\xc4',
  b'\xc8', b'\x9e', b'\xea', b'\xbf', b'\x8a', b'\xd2', b'\x40', b'\xc7', b'\x38',
  b'\xb5', b'\xa3', b'\xf7', b'\xf2', b'\xce', b'\xf9', b'\x61', b'\x15', b'\xa1',
  b'\xe0', b'\xae', b'\x5d', b'\xa4', b'\x9b', b'\x34', b'\x1a', b'\x55', b'\xad',
  b'\x93', b'\x32', b'\x30', b'\xf5', b'\x8c', b'\xb1', b'\xe3', b'\x1d', b'\xf6',
  b'\xe2', b'\x2e', b'\x82', b'\x66', b'\xca', b'\x60', b'\xc0', b'\x29', b'\x23',
  b'\xab', b'\x0d', b'\x53', b'\x4e', b'\x6f', b'\xd5', b'\xdb', b'\x37', b'\x45',
  b'\xde', b'\xfd', b'\x8e', b'\x2f', b'\x03', b'\xff', b'\x6a', b'\x72', b'\x6d',
  b'\x6c', b'\x5b', b'\x51', b'\x8d', b'\x1b', b'\xaf', b'\x92', b'\xbb', b'\xdd',
  b'\xbc', b'\x7f', b'\x11', b'\xd9', b'\x5c', b'\x41', b'\x1f', b'\x10', b'\x5a',
  b'\xd8', b'\x0a', b'\xc1', b'\x31', b'\x88', b'\xa5', b'\xcd', b'\x7b', b'\xbd',
  b'\x2d', b'\x74', b'\xd0', b'\x12', b'\xb8', b'\xe5', b'\xb4', b'\xb0', b'\x89',
  b'\x69', b'\x97', b'\x4a', b'\x0c', b'\x96', b'\x77', b'\x7e', b'\x65', b'\xb9',
  b'\xf1', b'\x09', b'\xc5', b'\x6e', b'\xc6', b'\x84', b'\x18', b'\xf0', b'\x7d',
  b'\xec', b'\x3a', b'\xdc', b'\x4d', b'\x20', b'\x79', b'\xee', b'\x5f', b'\x3e',
  b'\xd7', b'\xcb', b'\x39', b'\x48',
]

///|
/// System parameters fk (GM/T 0002-2012 Appendix A.1).
let fk : FixedArray[UInt] = [0xA3B1BAC6U, 0x56AA3350U, 0x677D9197U, 0xB27022DCU]

///|
/// Fixed parameters ck (GM/T 0002-2012 Appendix A.2).
/// ck[i][j] = (4i + j) × 7 mod 256
let ck : FixedArray[UInt] = FixedArray::makei(32, fn(i) {
  let base = (i * 4).reinterpret_as_uint()
  (((base * 7U) & 0xFFU) << 24) |
  ((((base + 1U) * 7U) & 0xFFU) << 16) |
  ((((base + 2U) * 7U) & 0xFFU) << 8) |
  (((base + 3U) * 7U) & 0xFFU)
})

///|
pub suberror SM4Error {
  InvalidKey // key length != 16 bytes
  InvalidData // data length not a multiple of 16
  InvalidIV // IV not empty and length != 16 bytes
  InvalidPadding // PKCS7 unpadding: padding value invalid
  DecryptFailed // CBC decrypt failed
} derive(Debug, Eq)

///|
/// Returns the DecryptFailed error (constructs the variant for API completeness).
pub fn sm4_error_decrypt_failed() -> SM4Error {
  DecryptFailed
}

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
/// Non-linear transformation τ: substitute each byte via S-Box.
fn sm4_tau(a : UInt) -> UInt {
  let a0 = ((a >> 24) & 0xFFU).reinterpret_as_int()
  let a1 = ((a >> 16) & 0xFFU).reinterpret_as_int()
  let a2 = ((a >> 8) & 0xFFU).reinterpret_as_int()
  let a3 = (a & 0xFFU).reinterpret_as_int()
  (sbox[a0].to_uint() << 24) |
  (sbox[a1].to_uint() << 16) |
  (sbox[a2].to_uint() << 8) |
  sbox[a3].to_uint()
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
fn sm4_expand_key(key : Bytes) -> FixedArray[UInt] raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }

  let mk : FixedArray[UInt] = FixedArray::makei(4, fn(i) {
    get_u32_be(key, i * 4)
  })

  // K[0..3] = MK[i] ⊕ fk[i]
  let k : FixedArray[UInt] = FixedArray::makei(36, fn(i) {
    if i < 4 {
      mk[i] ^ fk[i]
    } else {
      0U
    }
  })

  // rk[0..31]
  let rk : FixedArray[UInt] = FixedArray::makei(32, fn(_i) { 0U })

  for i = 0; i < 32; i = i + 1 {
    k[i + 4] = k[i] ^ sm4_T_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck[i])
    rk[i] = k[i + 4]
  }

  rk
}

///|
/// Process one 128-bit block through SM4 with the given round keys.
fn sm4_process_block(
  x : FixedArray[UInt],
  rk : FixedArray[UInt],
) -> FixedArray[UInt] {
  let n = 4
  let xv : FixedArray[UInt] = FixedArray::makei(36, fn(i) {
    if i < n {
      x[i]
    } else {
      0U
    }
  })

  for i = 0; i < 32; i = i + 1 {
    xv[i + n] = sm4_F(xv[i], xv[i + 1], xv[i + 2], xv[i + 3], rk[i])
  }

  FixedArray::makei(4, fn(i) { xv[35 - i] })
}

///|
/// Single block encryption: key and data must each be 16 bytes.
/// Returns 16-byte ciphertext.
pub fn sm4_encrypt_block(key : Bytes, data : Bytes) -> Bytes raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  if data.length() != 16 {
    raise SM4Error::InvalidData
  }

  let rk = sm4_expand_key(key)
  let x : FixedArray[UInt] = FixedArray::makei(4, fn(i) {
    get_u32_be(data, i * 4)
  })

  let y = sm4_process_block(x, rk)
  Bytes::makei(16, fn(i) {
    let word = y[i / 4]
    let shift = 24 - i % 4 * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// Single block decryption: key and data must each be 16 bytes.
/// Returns 16-byte plaintext.
pub fn sm4_decrypt_block(key : Bytes, data : Bytes) -> Bytes raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  if data.length() != 16 {
    raise SM4Error::InvalidData
  }

  let rk = sm4_expand_key(key)

  // Reverse round keys for decryption
  let rk_rev : FixedArray[UInt] = FixedArray::makei(32, fn(i) { rk[31 - i] })

  let x : FixedArray[UInt] = FixedArray::makei(4, fn(i) {
    get_u32_be(data, i * 4)
  })

  let y = sm4_process_block(x, rk_rev)
  Bytes::makei(16, fn(i) {
    let word = y[i / 4]
    let shift = 24 - i % 4 * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// ECB mode encryption: data length must be a multiple of 16.
pub fn sm4_encrypt_ecb(key : Bytes, data : Bytes) -> Bytes raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  if data.length() % 16 != 0 {
    raise SM4Error::InvalidData
  }

  let rk = sm4_expand_key(key)
  let n_blocks = data.length() / 16
  // Pre-compute all result blocks as flat array of 32-bit words
  let result_words : FixedArray[UInt] = FixedArray::makei(n_blocks * 4, fn(_i) {
    0U
  })
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
    let shift = 24 - i % 4 * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// ECB mode decryption: data length must be a multiple of 16.
pub fn sm4_decrypt_ecb(key : Bytes, data : Bytes) -> Bytes raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  if data.length() % 16 != 0 {
    raise SM4Error::InvalidData
  }

  let rk = sm4_expand_key(key)
  let rk_rev : FixedArray[UInt] = FixedArray::makei(32, fn(i) { rk[31 - i] })
  let n_blocks = data.length() / 16
  let result_words : FixedArray[UInt] = FixedArray::makei(n_blocks * 4, fn(_i) {
    0U
  })
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
    let shift = 24 - i % 4 * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// CBC mode encryption. IV must be 16 bytes.
pub fn sm4_encrypt_cbc(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  if iv.length() != 16 {
    raise SM4Error::InvalidIV
  }
  if data.length() % 16 != 0 {
    raise SM4Error::InvalidData
  }

  let rk = sm4_expand_key(key)
  let n_blocks = data.length() / 16
  let result_words : FixedArray[UInt] = FixedArray::makei(n_blocks * 4, fn(_i) {
    0U
  })
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
    let xored : FixedArray[UInt] = FixedArray::makei(4, fn(j) {
      plain[j] ^ prev[j]
    })
    let encrypted = sm4_process_block(xored, rk)
    for j = 0; j < 4; j = j + 1 {
      result_words[b * 4 + j] = encrypted[j]
    }
  }
  Bytes::makei(data.length(), fn(i) {
    let word_idx = i / 4
    let word = result_words[word_idx]
    let shift = 24 - i % 4 * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// CBC mode decryption. IV must be 16 bytes. Data length must be a multiple of 16.
pub fn sm4_decrypt_cbc(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  if iv.length() != 16 {
    raise SM4Error::InvalidIV
  }
  if data.length() % 16 != 0 {
    raise SM4Error::InvalidData
  }

  let rk = sm4_expand_key(key)
  let rk_rev : FixedArray[UInt] = FixedArray::makei(32, fn(i) { rk[31 - i] })
  let n_blocks = data.length() / 16
  let result_words : FixedArray[UInt] = FixedArray::makei(n_blocks * 4, fn(_i) {
    0U
  })
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
    let shift = 24 - i % 4 * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// PKCS7 padding.
pub fn pkcs7_pad(data : Bytes, block_size : Int) -> Bytes {
  let pad_len = block_size - data.length() % block_size
  let pad_byte = pad_len.to_byte()
  Bytes::makei(data.length() + pad_len, fn(i) {
    if i < data.length() {
      data[i]
    } else {
      pad_byte
    }
  })
}

///|
/// PKCS7 unpadding. Removes the padding and returns the original data.
pub fn pkcs7_unpad(data : Bytes) -> Bytes raise SM4Error {
  if data.length() == 0 {
    raise SM4Error::InvalidPadding
  }
  let pad_len = data[data.length() - 1].to_int()
  if pad_len < 1 || pad_len > 16 {
    raise SM4Error::InvalidPadding
  }
  if pad_len > data.length() {
    raise SM4Error::InvalidPadding
  }

  // Verify all padding bytes are correct
  for i = data.length() - pad_len; i < data.length(); i = i + 1 {
    if data[i].to_int() != pad_len {
      raise SM4Error::InvalidPadding
    }
  }

  data[0:data.length() - pad_len].to_owned()
}

///|
/// Convert a 16-byte block (Bytes) into 4 big-endian 32-bit words.
fn block_to_words(b : Bytes) -> FixedArray[UInt] {
  FixedArray::makei(4, fn(i) { get_u32_be(b, i * 4) })
}

///|
/// Convert 4 big-endian 32-bit words back into a 16-byte block.
fn words_to_block(w : FixedArray[UInt]) -> Bytes {
  Bytes::makei(16, fn(i) {
    let word = w[i / 4]
    let shift = 24 - i % 4 * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
/// Encrypt a single 16-byte block using pre-expanded round keys (forward).
fn sm4_block(rk : FixedArray[UInt], block : Bytes) -> Bytes {
  words_to_block(sm4_process_block(block_to_words(block), rk))
}

///|
/// CFB mode (128-bit feedback). `encrypt = true` for encryption, `false` for
/// decryption. Data length must be a multiple of 16 (raw mode, no padding).
/// Mirrors tjfoc/gmsm `sm4.Sm4CFB` but with an explicit `iv` parameter and
/// without the internal PKCS7 padding (consistent with this package's
/// ECB/CBC API, which also requires block-aligned input).
fn sm4_cfb(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
  encrypt : Bool,
) -> Bytes raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  if iv.length() != 16 {
    raise SM4Error::InvalidIV
  }
  if data.length() % 16 != 0 {
    raise SM4Error::InvalidData
  }
  let rk = sm4_expand_key(key)
  let n = data.length() / 16
  let out : FixedArray[Byte] = FixedArray::makei(data.length(), fn(_) {
    b'\x00'
  })
  let mut reg : Bytes = iv
  for b = 0; b < n; b = b + 1 {
    let ks = sm4_block(rk, reg)
    let base = b * 16
    for j = 0; j < 16; j = j + 1 {
      out[base + j] = (ks[j].to_uint() ^ data[base + j].to_uint()).to_byte()
    }
    if encrypt {
      reg = Bytes::makei(16, fn(j) { out[base + j] })
    } else {
      reg = Bytes::makei(16, fn(j) { data[base + j] })
    }
  }
  Bytes::makei(data.length(), fn(i) { out[i] })
}

///|
/// CFB mode encryption (128-bit feedback). `data` length must be a multiple of 16.
pub fn sm4_encrypt_cfb(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise SM4Error {
  sm4_cfb(key, iv, data, true)
}

///|
/// CFB mode decryption (128-bit feedback). `data` length must be a multiple of 16.
pub fn sm4_decrypt_cfb(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise SM4Error {
  sm4_cfb(key, iv, data, false)
}

///|
/// OFB mode (128-bit feedback). Encryption and decryption are identical.
/// Data length must be a multiple of 16 (raw mode, no padding). Mirrors
/// tjfoc/gmsm `sm4.Sm4OFB` with an explicit `iv` parameter.
fn sm4_ofb(key : Bytes, iv : Bytes, data : Bytes) -> Bytes raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  if iv.length() != 16 {
    raise SM4Error::InvalidIV
  }
  if data.length() % 16 != 0 {
    raise SM4Error::InvalidData
  }
  let rk = sm4_expand_key(key)
  let n = data.length() / 16
  let out : FixedArray[Byte] = FixedArray::makei(data.length(), fn(_) {
    b'\x00'
  })
  let mut reg : Bytes = iv
  for b = 0; b < n; b = b + 1 {
    let ks = sm4_block(rk, reg)
    let base = b * 16
    for j = 0; j < 16; j = j + 1 {
      out[base + j] = (ks[j].to_uint() ^ data[base + j].to_uint()).to_byte()
    }
    reg = ks
  }
  Bytes::makei(data.length(), fn(i) { out[i] })
}

///|
/// OFB mode encryption (128-bit feedback). `data` length must be a multiple of 16.
pub fn sm4_encrypt_ofb(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise SM4Error {
  sm4_ofb(key, iv, data)
}

///|
/// OFB mode decryption (128-bit feedback). `data` length must be a multiple of 16.
pub fn sm4_decrypt_ofb(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise SM4Error {
  sm4_ofb(key, iv, data)
}

///|
/// GF(2^128) multiplication (used by GHASH). `x` and `y` are 16-byte blocks.
/// R = 0xe1 || 0^120 (the GCM reduction constant).
fn gf_mult_arr(x : FixedArray[Byte], y : Bytes) -> FixedArray[Byte] {
  let r : FixedArray[Byte] = FixedArray::makei(16, fn(i) {
    if i == 0 {
      b'\xe1'
    } else {
      b'\x00'
    }
  })
  let z : FixedArray[Byte] = FixedArray::makei(16, fn(_) { b'\x00' })
  let v : FixedArray[Byte] = FixedArray::makei(16, fn(i) { x[i] })
  for i = 0; i < 128; i = i + 1 {
    let yi = (y[i / 8].to_uint() >> (7 - i % 8)) & 1U
    if yi == 1U {
      for k = 0; k < 16; k = k + 1 {
        z[k] = (z[k].to_uint() ^ v[k].to_uint()).to_byte()
      }
    }
    let lsb = v[15].to_uint() & 1U
    for k = 15; k >= 0; k = k - 1 {
      let shifted = v[k].to_uint() >> 1
      if k > 0 {
        let carry = (v[k - 1].to_uint() & 1U) << 7
        v[k] = (shifted ^ carry).to_byte()
      } else {
        v[k] = shifted.to_byte()
      }
    }
    if lsb == 1U {
      for k = 0; k < 16; k = k + 1 {
        v[k] = (v[k].to_uint() ^ r[k].to_uint()).to_byte()
      }
    }
  }
  z
}

///|
/// GHASH over additional data `a` and ciphertext `c` (both arbitrary length,
/// zero-padded to 16-byte blocks). `h` is the GHASH subkey E_K(0^128).
fn ghash(h : Bytes, a : Bytes, c : Bytes) -> Bytes {
  let mut x : FixedArray[Byte] = FixedArray::makei(16, fn(_) { b'\x00' })
  let a_blocks = (a.length() + 15) / 16
  for i = 0; i < a_blocks; i = i + 1 {
    for k = 0; k < 16; k = k + 1 {
      let idx = i * 16 + k
      let bk = if idx < a.length() { a[idx] } else { b'\x00' }
      x[k] = (x[k].to_uint() ^ bk.to_uint()).to_byte()
    }
    x = gf_mult_arr(x, h)
  }
  let c_blocks = (c.length() + 15) / 16
  for i = 0; i < c_blocks; i = i + 1 {
    for k = 0; k < 16; k = k + 1 {
      let idx = i * 16 + k
      let bk = if idx < c.length() { c[idx] } else { b'\x00' }
      x[k] = (x[k].to_uint() ^ bk.to_uint()).to_byte()
    }
    x = gf_mult_arr(x, h)
  }
  // length block: 64-bit length of A || 64-bit length of C.
  // NOTE: mirrors tjfoc/gmsm `GHASH`, which uses *byte* lengths here (not the
  // bit lengths required by the GCM specification).
  // Use UInt64 so the 56-bit right shifts stay within range (a 32-bit UInt
  // would reduce shifts >= 32 modulo 32 and corrupt the block).
  let a_len : UInt64 = a.length().reinterpret_as_uint().to_uint64()
  let c_len : UInt64 = c.length().reinterpret_as_uint().to_uint64()
  for k = 0; k < 8; k = k + 1 {
    let bk = ((a_len >> (56 - k * 8)) & 0xFFUL).to_uint().to_byte()
    x[k] = (x[k].to_uint() ^ bk.to_uint()).to_byte()
  }
  for k = 0; k < 8; k = k + 1 {
    let bk = ((c_len >> (56 - k * 8)) & 0xFFUL).to_uint().to_byte()
    x[8 + k] = (x[8 + k].to_uint() ^ bk.to_uint()).to_byte()
  }
  x = gf_mult_arr(x, h)
  Bytes::makei(16, fn(i) { x[i] })
}

///|
/// Initial counter block J0. For a 96-bit IV: J0 = IV || 0x00000001.
/// Otherwise: J0 = GHASH(H, "", IV).
fn gcm_get_y0(h : Bytes, iv : Bytes) -> Bytes {
  if iv.length() * 8 == 96 {
    let y0 : FixedArray[Byte] = FixedArray::makei(16, fn(i) {
      if i < iv.length() {
        iv[i]
      } else if i == 15 {
        b'\x01'
      } else {
        b'\x00'
      }
    })
    Bytes::makei(16, fn(i) { y0[i] })
  } else {
    ghash(h, Bytes::makei(0, fn(_) { b'\x00' }), iv)
  }
}

///|
/// Increment the 128-bit counter block by 1. Mirrors tjfoc/gmsm `addYone`
/// (used by `incr`). The arithmetic is done byte-wise (mod 256), so a byte
/// equal to `0xff` plus a carry wraps to `0x00` *and* stays `0x00` (the
/// incoming carry is absorbed), rather than producing `0x01`. This quirk is
/// required so the generated counter blocks match `sm4.Sm4GCM`'s output
/// byte-for-byte.
fn gcm_inc(y : Bytes) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::makei(16, fn(i) { y[i] })
  let mut rc : UInt = 0U
  for k = 15; k >= 0; k = k - 1 {
    if k == 15 {
      if out[15].to_uint() < 0xFFU {
        out[15] = (out[15].to_uint() + 1U).to_byte()
        rc = 0U
      } else {
        out[15] = b'\x00'
        rc = 1U
      }
    } else {
      let s = (out[k].to_uint() + rc) & 0xFFU
      if s < 0xFFU {
        out[k] = s.to_byte()
        rc = 0U
      } else {
        out[k] = b'\x00'
        rc = 1U
      }
    }
  }
  Bytes::makei(16, fn(i) { out[i] })
}

///|
/// SM4 GCM authenticated encryption. Returns `(ciphertext, tag)`.
/// `iv` may be any length (96-bit IV uses the standard J0 form); `plaintext`
/// and `aad` are arbitrary length (no padding). Mirrors tjfoc/gmsm
/// `sm4.Sm4GCM` / `GCMEncrypt` (tag length 16 bytes / 128 bits).
pub fn sm4_gcm_encrypt(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
  aad : Bytes,
) -> (Bytes, Bytes) raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  let rk = sm4_expand_key(key)
  let h = sm4_block(rk, Bytes::makei(16, fn(_) { b'\x00' }))
  let y0 = gcm_get_y0(h, iv)
  let l = plaintext.length()
  let n = if l == 0 { 1 } else { (l + 15) / 16 }
  let yblocks : FixedArray[Bytes] = FixedArray::makei(n + 1, fn(_) {
    Bytes::makei(16, fn(_) { b'\x00' })
  })
  yblocks[0] = y0
  for i = 1; i <= n; i = i + 1 {
    yblocks[i] = gcm_inc(yblocks[i - 1])
  }
  let cipher : FixedArray[Byte] = FixedArray::makei(l, fn(_) { b'\x00' })
  for i = 1; i <= n - 1; i = i + 1 {
    let ek = sm4_block(rk, yblocks[i])
    let base = (i - 1) * 16
    for j = 0; j < 16; j = j + 1 {
      cipher[base + j] = (ek[j].to_uint() ^ plaintext[base + j].to_uint()).to_byte()
    }
  }
  let ek = sm4_block(rk, yblocks[n])
  let nb = if l == 0 { 0 } else { l - (n - 1) * 16 }
  let base = (n - 1) * 16
  for j = 0; j < nb; j = j + 1 {
    cipher[base + j] = (ek[j].to_uint() ^ plaintext[base + j].to_uint()).to_byte()
  }
  let c = Bytes::makei(l, fn(i) { cipher[i] })
  let ey0 = sm4_block(rk, y0)
  let s = ghash(h, aad, c)
  let tag : FixedArray[Byte] = FixedArray::makei(16, fn(i) {
    (ey0[i].to_uint() ^ s[i].to_uint()).to_byte()
  })
  (c, Bytes::makei(16, fn(i) { tag[i] }))
}

///|
/// SM4 GCM decryption. Returns `(plaintext, tag)`. Note: like tjfoc/gmsm
/// `sm4.Sm4GCM` / `GCMDecrypt`, this does **not** verify the tag — the caller
/// must compare the returned `tag` against the expected value (preferably in
/// constant time) before trusting `plaintext`.
pub fn sm4_gcm_decrypt(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
  aad : Bytes,
) -> (Bytes, Bytes) raise SM4Error {
  if key.length() != 16 {
    raise SM4Error::InvalidKey
  }
  let rk = sm4_expand_key(key)
  let h = sm4_block(rk, Bytes::makei(16, fn(_) { b'\x00' }))
  let y0 = gcm_get_y0(h, iv)
  let l = ciphertext.length()
  let n = if l == 0 { 1 } else { (l + 15) / 16 }
  let yblocks : FixedArray[Bytes] = FixedArray::makei(n + 1, fn(_) {
    Bytes::makei(16, fn(_) { b'\x00' })
  })
  yblocks[0] = y0
  for i = 1; i <= n; i = i + 1 {
    yblocks[i] = gcm_inc(yblocks[i - 1])
  }
  let ey0 = sm4_block(rk, y0)
  let s = ghash(h, aad, ciphertext)
  let tag : FixedArray[Byte] = FixedArray::makei(16, fn(i) {
    (ey0[i].to_uint() ^ s[i].to_uint()).to_byte()
  })
  let plain : FixedArray[Byte] = FixedArray::makei(l, fn(_) { b'\x00' })
  for i = 1; i <= n - 1; i = i + 1 {
    let ek = sm4_block(rk, yblocks[i])
    let base = (i - 1) * 16
    for j = 0; j < 16; j = j + 1 {
      plain[base + j] = (ek[j].to_uint() ^ ciphertext[base + j].to_uint()).to_byte()
    }
  }
  let nb = if l == 0 { 0 } else { l - (n - 1) * 16 }
  let base = (n - 1) * 16
  let ek = sm4_block(rk, yblocks[n])
  for j = 0; j < nb; j = j + 1 {
    plain[base + j] = (ek[j].to_uint() ^ ciphertext[base + j].to_uint()).to_byte()
  }
  (Bytes::makei(l, fn(i) { plain[i] }), Bytes::makei(16, fn(i) { tag[i] }))
}
