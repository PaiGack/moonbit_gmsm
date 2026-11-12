/// Minimal AES-256-CBC, used only by the legacy encrypted-PEM reader/writer in
/// `utils.mbt`.
///
/// gmsm encrypts `SM4 ENCRYPTED KEY` blocks with `x509.EncryptPEMBlock(...
/// x509.PEMCipherAES256)`, whose key derivation is simply the passphrase
/// padded with zero bytes to 32 bytes. Reproducing that format interoperably
/// therefore needs AES itself. This is a straightforward table-free
/// implementation intended for key files, not for bulk data.
///
/// The block cipher follows FIPS-197: 14 rounds for a 256-bit key.

///|
/// AES S-box.
let aes_sbox : FixedArray[Byte] = [
  b'\x63', b'\x7c', b'\x77', b'\x7b', b'\xf2', b'\x6b', b'\x6f', b'\xc5', b'\x30',
  b'\x01', b'\x67', b'\x2b', b'\xfe', b'\xd7', b'\xab', b'\x76', b'\xca', b'\x82',
  b'\xc9', b'\x7d', b'\xfa', b'\x59', b'\x47', b'\xf0', b'\xad', b'\xd4', b'\xa2',
  b'\xaf', b'\x9c', b'\xa4', b'\x72', b'\xc0', b'\xb7', b'\xfd', b'\x93', b'\x26',
  b'\x36', b'\x3f', b'\xf7', b'\xcc', b'\x34', b'\xa5', b'\xe5', b'\xf1', b'\x71',
  b'\xd8', b'\x31', b'\x15', b'\x04', b'\xc7', b'\x23', b'\xc3', b'\x18', b'\x96',
  b'\x05', b'\x9a', b'\x07', b'\x12', b'\x80', b'\xe2', b'\xeb', b'\x27', b'\xb2',
  b'\x75', b'\x09', b'\x83', b'\x2c', b'\x1a', b'\x1b', b'\x6e', b'\x5a', b'\xa0',
  b'\x52', b'\x3b', b'\xd6', b'\xb3', b'\x29', b'\xe3', b'\x2f', b'\x84', b'\x53',
  b'\xd1', b'\x00', b'\xed', b'\x20', b'\xfc', b'\xb1', b'\x5b', b'\x6a', b'\xcb',
  b'\xbe', b'\x39', b'\x4a', b'\x4c', b'\x58', b'\xcf', b'\xd0', b'\xef', b'\xaa',
  b'\xfb', b'\x43', b'\x4d', b'\x33', b'\x85', b'\x45', b'\xf9', b'\x02', b'\x7f',
  b'\x50', b'\x3c', b'\x9f', b'\xa8', b'\x51', b'\xa3', b'\x40', b'\x8f', b'\x92',
  b'\x9d', b'\x38', b'\xf5', b'\xbc', b'\xb6', b'\xda', b'\x21', b'\x10', b'\xff',
  b'\xf3', b'\xd2', b'\xcd', b'\x0c', b'\x13', b'\xec', b'\x5f', b'\x97', b'\x44',
  b'\x17', b'\xc4', b'\xa7', b'\x7e', b'\x3d', b'\x64', b'\x5d', b'\x19', b'\x73',
  b'\x60', b'\x81', b'\x4f', b'\xdc', b'\x22', b'\x2a', b'\x90', b'\x88', b'\x46',
  b'\xee', b'\xb8', b'\x14', b'\xde', b'\x5e', b'\x0b', b'\xdb', b'\xe0', b'\x32',
  b'\x3a', b'\x0a', b'\x49', b'\x06', b'\x24', b'\x5c', b'\xc2', b'\xd3', b'\xac',
  b'\x62', b'\x91', b'\x95', b'\xe4', b'\x79', b'\xe7', b'\xc8', b'\x37', b'\x6d',
  b'\x8d', b'\xd5', b'\x4e', b'\xa9', b'\x6c', b'\x56', b'\xf4', b'\xea', b'\x65',
  b'\x7a', b'\xae', b'\x08', b'\xba', b'\x78', b'\x25', b'\x2e', b'\x1c', b'\xa6',
  b'\xb4', b'\xc6', b'\xe8', b'\xdd', b'\x74', b'\x1f', b'\x4b', b'\xbd', b'\x8b',
  b'\x8a', b'\x70', b'\x3e', b'\xb5', b'\x66', b'\x48', b'\x03', b'\xf6', b'\x0e',
  b'\x61', b'\x35', b'\x57', b'\xb9', b'\x86', b'\xc1', b'\x1d', b'\x9e', b'\xe1',
  b'\xf8', b'\x98', b'\x11', b'\x69', b'\xd9', b'\x8e', b'\x94', b'\x9b', b'\x1e',
  b'\x87', b'\xe9', b'\xce', b'\x55', b'\x28', b'\xdf', b'\x8c', b'\xa1', b'\x89',
  b'\x0d', b'\xbf', b'\xe6', b'\x42', b'\x68', b'\x41', b'\x99', b'\x2d', b'\x0f',
  b'\xb0', b'\x54', b'\xbb', b'\x16',
]

///|
/// Inverse AES S-box.
let aes_inv_sbox : FixedArray[Byte] = FixedArray::makei(256, fn(i) {
  let mut j = 0
  while aes_sbox[j].to_int() != i {
    j = j + 1
  }
  j.to_byte()
})

///|
/// Round constant for key expansion.
fn aes_rcon(i : Int32) -> Byte {
  let mut v : UInt32 = 1
  for _ in 1..<i {
    // xtime
    let hi = v & 0x80U
    v = (v << 1) & 0xFFU
    if hi != 0U {
      v = v ^ 0x1BU
    }
  }
  v.to_byte()
}

///|
/// Expand a 32-byte AES-256 key into 15 round keys (60 words, 240 bytes).
///
/// FIPS-197 section 5.2: for `i >= 8`, word `w[i] = w[i-8] ^ temp`, where
/// `temp = SubWord(RotWord(w[i-1])) ^ Rcon(i/8)` when `i % 8 == 0`, and
/// `temp = SubWord(w[i-1])` when `i % 8 == 4`; otherwise `temp = w[i-1]`.
fn aes256_expand_key(key : Bytes) -> FixedArray[Byte] raise SM4Error {
  if key.length() != 32 {
    raise SM4Error::InvalidKey
  }
  // 60 words, each held in its own mutable 4-byte array.
  let words : Array[FixedArray[Byte]] = []
  for i = 0; i < 8; i = i + 1 {
    let word : FixedArray[Byte] = FixedArray::make(4, b'\x00')
    for j = 0; j < 4; j = j + 1 {
      word[j] = key[i * 4 + j]
    }
    words.push(word)
  }
  let mut i = 8
  while i < 60 {
    let prev = words[i - 1]
    let temp : FixedArray[Byte] = FixedArray::make(4, b'\x00')
    if i % 8 == 0 {
      temp[0] = (aes_sbox[prev[1].to_int()].to_int() ^ aes_rcon(i / 8).to_int()).to_byte()
      temp[1] = aes_sbox[prev[2].to_int()]
      temp[2] = aes_sbox[prev[3].to_int()]
      temp[3] = aes_sbox[prev[0].to_int()]
    } else if i % 8 == 4 {
      for j = 0; j < 4; j = j + 1 {
        temp[j] = aes_sbox[prev[j].to_int()]
      }
    } else {
      for j = 0; j < 4; j = j + 1 {
        temp[j] = prev[j]
      }
    }
    let base = words[i - 8]
    let word : FixedArray[Byte] = FixedArray::make(4, b'\x00')
    for j = 0; j < 4; j = j + 1 {
      word[j] = (base[j].to_int() ^ temp[j].to_int()).to_byte()
    }
    words.push(word)
    i = i + 1
  }
  FixedArray::makei(240, fn(k) { words[k / 4][k % 4] })
}

///|
/// Multiplication by x in GF(2^8).
fn aes_xtime(b : Int32) -> Int32 {
  let hi = b & 0x80
  let v = (b << 1) & 0xFF
  if hi != 0 {
    v ^ 0x1B
  } else {
    v
  }
}

///|
/// Multiply two bytes in GF(2^8).
fn aes_mul(a : Int32, b : Int32) -> Int32 {
  let mut x = a
  let mut y = b
  let mut r = 0
  for _ in 0..<8 {
    if (y & 1) != 0 {
      r = r ^ x
    }
    x = aes_xtime(x)
    y = y >> 1
  }
  r
}

///|
/// Add the round key to the state, column-major (byte i is row i%4, col i/4).
fn aes_add_round_key(
  state : FixedArray[Byte],
  w : FixedArray[Byte],
  round : Int32,
) -> Unit {
  for c = 0; c < 4; c = c + 1 {
    for r = 0; r < 4; r = r + 1 {
      // Round key word `c` of `round` occupies bytes ((round*4+c)*4 .. +4).
      state[c * 4 + r] = (state[c * 4 + r].to_int() ^
      w[(round * 4 + c) * 4 + r].to_int()).to_byte()
    }
  }
}

///|
fn aes_sub_bytes(state : FixedArray[Byte]) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    state[i] = aes_sbox[state[i].to_int()]
  }
}

///|
fn aes_inv_sub_bytes(state : FixedArray[Byte]) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    state[i] = aes_inv_sbox[state[i].to_int()]
  }
}

///|
/// ShiftRows: row r rotates left by r columns.
fn aes_shift_rows(state : FixedArray[Byte]) -> Unit {
  let s = state.copy()
  for c = 0; c < 4; c = c + 1 {
    for r = 0; r < 4; r = r + 1 {
      state[c * 4 + r] = s[(c + r) % 4 * 4 + r]
    }
  }
}

///|
fn aes_inv_shift_rows(state : FixedArray[Byte]) -> Unit {
  let s = state.copy()
  for c = 0; c < 4; c = c + 1 {
    for r = 0; r < 4; r = r + 1 {
      state[c * 4 + r] = s[(c + 4 - r) % 4 * 4 + r]
    }
  }
}

///|
fn aes_mix_columns(state : FixedArray[Byte]) -> Unit {
  for c = 0; c < 4; c = c + 1 {
    let a0 = state[c * 4].to_int()
    let a1 = state[c * 4 + 1].to_int()
    let a2 = state[c * 4 + 2].to_int()
    let a3 = state[c * 4 + 3].to_int()
    state[c * 4] = (aes_xtime(a0) ^ (aes_xtime(a1) ^ a1) ^ a2 ^ a3).to_byte()
    state[c * 4 + 1] = (a0 ^ aes_xtime(a1) ^ (aes_xtime(a2) ^ a2) ^ a3).to_byte()
    state[c * 4 + 2] = (a0 ^ a1 ^ aes_xtime(a2) ^ (aes_xtime(a3) ^ a3)).to_byte()
    state[c * 4 + 3] = (aes_xtime(a0) ^ a0 ^ a1 ^ a2 ^ aes_xtime(a3)).to_byte()
  }
}

///|
fn aes_inv_mix_columns(state : FixedArray[Byte]) -> Unit {
  for c = 0; c < 4; c = c + 1 {
    let a0 = state[c * 4].to_int()
    let a1 = state[c * 4 + 1].to_int()
    let a2 = state[c * 4 + 2].to_int()
    let a3 = state[c * 4 + 3].to_int()
    state[c * 4] = (aes_mul(a0, 14) ^
    aes_mul(a1, 11) ^
    aes_mul(a2, 13) ^
    aes_mul(a3, 9)).to_byte()
    state[c * 4 + 1] = (aes_mul(a0, 9) ^
    aes_mul(a1, 14) ^
    aes_mul(a2, 11) ^
    aes_mul(a3, 13)).to_byte()
    state[c * 4 + 2] = (aes_mul(a0, 13) ^
    aes_mul(a1, 9) ^
    aes_mul(a2, 14) ^
    aes_mul(a3, 11)).to_byte()
    state[c * 4 + 3] = (aes_mul(a0, 11) ^
    aes_mul(a1, 13) ^
    aes_mul(a2, 9) ^
    aes_mul(a3, 14)).to_byte()
  }
}

///|
/// Encrypt one 16-byte block with an expanded AES-256 key (240 bytes).
fn aes256_encrypt_block(w : FixedArray[Byte], block : Bytes) -> Bytes {
  let state : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    state[i] = block[i]
  }
  aes_add_round_key(state, w, 0)
  for round in 1..<14 {
    aes_sub_bytes(state)
    aes_shift_rows(state)
    aes_mix_columns(state)
    aes_add_round_key(state, w, round)
  }
  aes_sub_bytes(state)
  aes_shift_rows(state)
  aes_add_round_key(state, w, 14)
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    out[i] = state[i]
  }
  Bytes::makei(16, fn(i) { out[i] })
}

///|
fn aes256_decrypt_block(w : FixedArray[Byte], block : Bytes) -> Bytes {
  let state : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    state[i] = block[i]
  }
  aes_add_round_key(state, w, 14)
  for round = 13; round > 0; round = round - 1 {
    aes_inv_shift_rows(state)
    aes_inv_sub_bytes(state)
    aes_add_round_key(state, w, round)
    aes_inv_mix_columns(state)
  }
  aes_inv_shift_rows(state)
  aes_inv_sub_bytes(state)
  aes_add_round_key(state, w, 0)
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    out[i] = state[i]
  }
  Bytes::makei(16, fn(i) { out[i] })
}

///|
/// AES-256-CBC encrypt (PKCS#7 padding is *not* applied here).
fn aes256_cbc_encrypt_raw(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise SM4Error {
  if data.length() % 16 != 0 || iv.length() != 16 {
    raise SM4Error::InvalidData
  }
  let w = aes256_expand_key(key)
  let out : FixedArray[Byte] = FixedArray::make(data.length(), b'\x00')
  let mut prev = iv
  let mut off = 0
  while off < data.length() {
    let blk = Bytes::makei(16, fn(i) {
      (data[off + i].to_int() ^ prev[i].to_int()).to_byte()
    })
    let enc = aes256_encrypt_block(w, blk)
    for i = 0; i < 16; i = i + 1 {
      out[off + i] = enc[i]
    }
    prev = enc
    off = off + 16
  }
  Bytes::makei(data.length(), fn(i) { out[i] })
}

///|
/// AES-256-CBC decrypt (keeps PKCS#7 padding).
fn aes256_cbc_decrypt_raw(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise SM4Error {
  if data.length() % 16 != 0 || iv.length() != 16 {
    raise SM4Error::InvalidData
  }
  let w = aes256_expand_key(key)
  let out : FixedArray[Byte] = FixedArray::make(data.length(), b'\x00')
  let mut prev = iv
  let mut off = 0
  while off < data.length() {
    let ct = data[off:off + 16].to_owned()
    let dec = aes256_decrypt_block(w, ct)
    for i = 0; i < 16; i = i + 1 {
      out[off + i] = (dec[i].to_int() ^ prev[i].to_int()).to_byte()
    }
    prev = ct
    off = off + 16
  }
  Bytes::makei(data.length(), fn(i) { out[i] })
}

///|
/// Legacy `x509.EncryptPEMBlock` key derivation: copy the passphrase into a
/// zeroed key-size buffer; passphrases longer than 32 bytes are truncated.
fn pem_legacy_key(pwd : Bytes, size : Int32) -> Bytes raise SM4Error {
  if pwd.length() > size {
    raise SM4Error::InvalidData
  }
  Bytes::makei(size, fn(i) { if i < pwd.length() { pwd[i] } else { b'\x00' } })
}
