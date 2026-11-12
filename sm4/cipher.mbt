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
/// Set the IV carried by this cipher, used by the `cbc_*` / `cfb_*` / `ofb_*`
/// helper methods below. Mirrors `sm4.SetIV`, but scoped to one cipher value
/// instead of the whole package.
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
/// Set the package-level default IV used by `sm4_cbc` / `sm4_cfb` /
/// `sm4_ofb`. Mirrors `sm4.SetIV`; the IV must be exactly 16 bytes.
pub fn set_iv(iv : Bytes) -> Unit raise SM4Error {
  if iv.length() != sm4_block_size {
    raise SM4Error::InvalidIV
  }
  for i in 0..<sm4_block_size {
    default_iv[i] = iv[i]
  }
}

///|
/// Return a copy of the package-level default IV.
pub fn get_iv() -> Bytes {
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
    @byteutil.pkcs7_unpad(sm4_decrypt_ecb(key, data)) catch {
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
  let iv = get_iv()
  if encrypt {
    sm4_encrypt_cbc(key, iv, @byteutil.pkcs7_pad(data, sm4_block_size))
  } else {
    @byteutil.pkcs7_unpad(sm4_decrypt_cbc(key, iv, data)) catch {
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
  let iv = get_iv()
  if encrypt {
    cfb_core(key, iv, @byteutil.pkcs7_pad(data, sm4_block_size), true)
  } else {
    @byteutil.pkcs7_unpad(cfb_core(key, iv, data, false)) catch {
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
  let iv = get_iv()
  if encrypt {
    ofb_core(key, iv, @byteutil.pkcs7_pad(data, sm4_block_size))
  } else {
    @byteutil.pkcs7_unpad(ofb_core(key, iv, data)) catch {
      _ => raise SM4Error::InvalidPadding
    }
  }
}

///|
/// GCM mode dispatcher. `encrypt = true` performs authenticated encryption
/// and returns `(ciphertext, tag)`. `encrypt = false` performs authenticated
/// decryption: when `data` is the ciphertext followed by its 16-byte tag,
/// the tag is verified in constant time and the returned pair is
/// `(plaintext, empty)`. A tag mismatch raises `SM4Error::InvalidTag` and no
/// plaintext is returned.
///
/// Input without an appended tag cannot be verified and is rejected with
/// `SM4Error::InvalidTag` (length 0 included). Use `sm4_gcm_decrypt` when the
/// tag is passed separately.
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
