/// tjfoc/gmsm-compatible surface for SM4:
/// - `new_cipher` returns a reusable pre-expanded key object, mirroring
///   `sm4.NewCipher` / `cipher.Block` (`BlockSize` / `Encrypt` / `Decrypt`).
/// - `set_iv` / `get_iv` maintain the package-level default IV, mirroring
///   `sm4.SetIV`.
/// - `sm4_ecb` / `sm4_cbc` / `sm4_cfb` / `sm4_ofb` are the `mode bool`
///   wrappers that apply PKCS7 padding internally, mirroring `sm4.Sm4Ecb`,
///   `sm4.Sm4Cbc`, `sm4.Sm4CFB` and `sm4.Sm4OFB`.

///|
/// SM4 block length in bytes (mirrors `sm4.BlockSize`).
pub let sm4_block_size : Int32 = 16

///|
/// SM4 key length in bytes.
pub let sm4_key_size : Int32 = 16

///|
/// A pre-expanded SM4 key. Mirrors the `cipher.Block` value returned by
/// `sm4.NewCipher`: the round keys are derived once and can then be reused
/// for any number of single-block operations.
pub struct SM4Cipher {
  rk : FixedArray[UInt32]
  rk_rev : FixedArray[UInt32]
  iv : FixedArray[Byte]
}

///|
/// Create a cipher from a 16-byte key. Mirrors `sm4.NewCipher`.
pub fn new_cipher(key : Bytes) -> SM4Cipher raise SM4Error {
  if key.length() != sm4_key_size {
    raise SM4Error::InvalidKey
  }
  let rk = sm4_expand_key(key)
  let rk_rev : FixedArray[UInt32] = FixedArray::makei(32, fn(i) { rk[31 - i] })
  SM4Cipher::{ rk, rk_rev, iv: FixedArray::makei(16, fn(_) { b'\x00' }), }
}

///|
/// Block length in bytes (16). Mirrors `cipher.Block.BlockSize`.
pub fn SM4Cipher::block_size(_self : SM4Cipher) -> Int32 {
  sm4_block_size
}

///|
/// Encrypt exactly one 16-byte block. Mirrors `cipher.Block.Encrypt`.
pub fn SM4Cipher::encrypt(
  self : SM4Cipher,
  block : Bytes,
) -> Bytes raise SM4Error {
  if block.length() != sm4_block_size {
    raise SM4Error::InvalidData
  }
  sm4_block(self.rk, block)
}

///|
/// Decrypt exactly one 16-byte block. Mirrors `cipher.Block.Decrypt`.
pub fn SM4Cipher::decrypt(
  self : SM4Cipher,
  block : Bytes,
) -> Bytes raise SM4Error {
  if block.length() != sm4_block_size {
    raise SM4Error::InvalidData
  }
  sm4_block(self.rk_rev, block)
}

///|
/// Zero the expanded round keys (and the stored IV) in place.
///
/// Call it once the cipher is no longer needed: MoonBit has no destructor, so
/// otherwise the round-key schedule stays in the heap until the collector
/// reclaims it. The cipher is unusable afterwards.
pub fn SM4Cipher::wipe(self : SM4Cipher) -> Unit {
  for i in 0..<32 {
    self.rk[i] = 0U
    self.rk_rev[i] = 0U
  }
  for i in 0..<sm4_block_size {
    self.iv[i] = b'\x00'
  }
}

///|
/// Set the IV carried by this cipher value (not shared across the package,
/// unlike the deprecated free `set_iv`). The IV is only stored; no `SM4Cipher`
/// method consumes it implicitly, so prefer passing the IV explicitly.
pub fn SM4Cipher::set_iv(self : SM4Cipher, iv : Bytes) -> Unit raise SM4Error {
  if iv.length() != sm4_block_size {
    raise SM4Error::InvalidIV
  }
  for i in 0..<sm4_block_size {
    self.iv[i] = iv[i]
  }
}

///|
/// Return a copy of the IV currently carried by this cipher.
pub fn SM4Cipher::get_iv(self : SM4Cipher) -> Bytes {
  Bytes::makei(sm4_block_size, fn(i) { self.iv[i] })
}

///|
/// Package-level default IV, mirroring the mutable `iv` package variable in
/// tjfoc/gmsm. Initialized to 16 zero bytes and updated through `set_iv`.
let default_iv : FixedArray[Byte] = FixedArray::makei(16, fn(_) { b'\x00' })

///|
/// Package-level IV mutator, kept only to mirror `sm4.SetIV`.
///
/// **Deprecated: do not use.** It is process-wide mutable state, so two
/// independent call sites silently overwrite each other's IV, and the initial
/// value is an all-zero IV — catastrophic for CBC (equal plaintext prefixes
/// leak) and for CFB/OFB (key + IV reuse turns the cipher into a broken stream
/// cipher). Prefer the explicit-IV entry points `sm4_encrypt_cbc` /
/// `sm4_encrypt_cfb` / `sm4_encrypt_ofb`, which take the IV as a parameter.
#deprecated("使用显式 IV 的 sm4_encrypt_cbc / sm4_encrypt_cfb / sm4_encrypt_ofb")
pub fn set_iv(iv : Bytes) -> Unit raise SM4Error {
  if iv.length() != sm4_block_size {
    raise SM4Error::InvalidIV
  }
  for i in 0..<sm4_block_size {
    default_iv[i] = iv[i]
  }
}

///|
/// Read the package-level IV. Deprecated together with `set_iv`; prefer the
/// explicit-IV entry points.
#deprecated("使用显式 IV 的 sm4_encrypt_cbc / sm4_encrypt_cfb / sm4_encrypt_ofb")
pub fn get_iv() -> Bytes {
  Bytes::makei(sm4_block_size, fn(i) { default_iv[i] })
}

///|
/// Un-deprecated aliases of `set_iv` / `get_iv` for tests and for
/// gmsm-compatibility shims that must keep using package-level state.
pub fn set_iv_unchecked(iv : Bytes) -> Unit raise SM4Error {
  if iv.length() != sm4_block_size {
    raise SM4Error::InvalidIV
  }
  for i in 0..<sm4_block_size {
    default_iv[i] = iv[i]
  }
}

///|
pub fn get_iv_unchecked() -> Bytes {
  default_iv_copy()
}

///|
/// Copy of the default IV for the `mode bool` wrappers below. Kept private so
/// the deprecated public `get_iv` can stay deprecated without the package
/// itself tripping the warning.
fn default_iv_copy() -> Bytes {
  Bytes::makei(sm4_block_size, fn(i) { default_iv[i] })
}

///|
/// ECB mode with internal PKCS7 padding. `encrypt = true` encrypts (input may
/// have any length), `false` decrypts (input must be block-aligned and end
/// with valid padding). Mirrors `sm4.Sm4Ecb`.
pub fn sm4_ecb(
  key : Bytes,
  data : Bytes,
  encrypt : Bool,
) -> Bytes raise SM4Error {
  if encrypt {
    sm4_encrypt_ecb(key, @byteutil.pkcs7_pad(data, sm4_block_size))
  } else {
    let plain = sm4_decrypt_ecb(key, data)
    @byteutil.pkcs7_unpad(plain) catch {
      _ => raise SM4Error::InvalidPadding
    }
  }
}

///|
/// CBC mode with internal PKCS7 padding, using the package-level default IV
/// (see `set_iv`). Mirrors `sm4.Sm4Cbc`.
pub fn sm4_cbc(
  key : Bytes,
  data : Bytes,
  encrypt : Bool,
) -> Bytes raise SM4Error {
  let iv = default_iv_copy()
  if encrypt {
    sm4_encrypt_cbc(key, iv, @byteutil.pkcs7_pad(data, sm4_block_size))
  } else {
    let plain = sm4_decrypt_cbc(key, iv, data)
    @byteutil.pkcs7_unpad(plain) catch {
      _ => raise SM4Error::InvalidPadding
    }
  }
}

///|
/// CFB mode (128-bit feedback) with internal PKCS7 padding, using the
/// package-level default IV (see `set_iv`). Mirrors `sm4.Sm4CFB`.
pub fn sm4_cfb(
  key : Bytes,
  data : Bytes,
  encrypt : Bool,
) -> Bytes raise SM4Error {
  let iv = default_iv_copy()
  if encrypt {
    cfb_core(key, iv, @byteutil.pkcs7_pad(data, sm4_block_size), true)
  } else {
    let plain = cfb_core(key, iv, data, false)
    @byteutil.pkcs7_unpad(plain) catch {
      _ => raise SM4Error::InvalidPadding
    }
  }
}

///|
/// OFB mode (128-bit feedback) with internal PKCS7 padding, using the
/// package-level default IV (see `set_iv`). Mirrors `sm4.Sm4OFB`.
pub fn sm4_ofb(
  key : Bytes,
  data : Bytes,
  encrypt : Bool,
) -> Bytes raise SM4Error {
  let iv = default_iv_copy()
  if encrypt {
    ofb_core(key, iv, @byteutil.pkcs7_pad(data, sm4_block_size))
  } else {
    let plain = ofb_core(key, iv, data)
    @byteutil.pkcs7_unpad(plain) catch {
      _ => raise SM4Error::InvalidPadding
    }
  }
}

///|
/// GCM mode dispatcher, mirroring `sm4.Sm4GCM`.
///
/// `encrypt = true` returns `(ciphertext, tag)`. `encrypt = false` requires
/// `data = ciphertext ‖ tag`, verifies the tag in constant time and returns
/// `(plaintext, empty)`; input shorter than 16 bytes carries no tag and is
/// rejected with `SM4Error::InvalidTag`.
///
/// Prefer `sm4_gcm_encrypt` / `sm4_gcm_decrypt`: they state their return
/// value and do not hand back a meaningless second element.
#deprecated("改用 sm4_gcm_encrypt / sm4_gcm_decrypt")
pub fn sm4_gcm(
  key : Bytes,
  iv : Bytes,
  data : Bytes,
  aad : Bytes,
  encrypt : Bool,
) -> (Bytes, Bytes) raise SM4Error {
  if encrypt {
    sm4_gcm_encrypt(key, iv, data, aad)
  } else {
    let n = data.length()
    if n < 16 {
      raise SM4Error::InvalidTag
    }
    let ct_len = n - 16
    let ct = data[0:ct_len].to_owned()
    let tag = data[ct_len:n].to_owned()
    let plain = sm4_gcm_decrypt(key, iv, ct, aad, tag)
    (plain, Bytes::makei(0, fn(_) { b'\x00' }))
  }
}
