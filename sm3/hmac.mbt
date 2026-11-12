/// HMAC-SM3 (RFC 2104) and PBKDF2-HMAC-SM3 (RFC 8018 / PKCS#5 v2.2).
///
/// Both are built on the streaming `SM3` context in `sm3.mbt`.

///|
/// Block size of SM3 in bytes, also the HMAC block size.
let hmac_block_size : Int32 = 64

///|
/// Errors raised by the HMAC-SM3 / PBKDF2-HMAC-SM3 helpers.
pub suberror HmacError {
  InvalidIterations // PBKDF2 iteration count must be >= 1
  InvalidLength // PBKDF2 output length must be >= 0
}

///|
#deprecated
pub extend HmacError with Eq::{not_equal, equal}

///|
pub impl Eq for HmacError with fn equal(self, other) {
  match (self, other) {
    (InvalidIterations, InvalidIterations) => true
    (InvalidLength, InvalidLength) => true
    _ => false
  }
}

///|
/// HMAC-SM3 keyed hash of `data`.
///
/// Keys longer than the 64-byte block are hashed with SM3 first; shorter
/// keys are zero-padded to the block size.
pub fn hmac_sm3(key : Bytes, data : Bytes) -> Bytes {
  let k = if key.length() > hmac_block_size { sm3_sum(key) } else { key }
  let ipad : FixedArray[Byte] = FixedArray::makei(hmac_block_size, fn(i) {
    if i < k.length() {
      (k[i].to_int() ^ 0x36).to_byte()
    } else {
      b'\x36'
    }
  })
  let opad : FixedArray[Byte] = FixedArray::makei(hmac_block_size, fn(i) {
    if i < k.length() {
      (k[i].to_int() ^ 0x5c).to_byte()
    } else {
      b'\x5c'
    }
  })
  let inner = new().write(Bytes::from_array(ipad)).write(data).finish()
  new().write(Bytes::from_array(opad)).write(inner).finish()
}

///|
/// PBKDF2 with HMAC-SM3 as the pseudorandom function.
///
/// `iterations` must be at least 1; `dk_len` is the requested output length in
/// bytes. The caller is responsible for choosing a salt of at least 16 bytes
/// and an iteration count appropriate for the deployment.
pub fn pbkdf2_hmac_sm3(
  password : Bytes,
  salt : Bytes,
  iterations : Int32,
  dk_len : Int32,
) -> Bytes raise HmacError {
  if iterations < 1 {
    raise HmacError::InvalidIterations
  }
  if dk_len < 0 {
    raise HmacError::InvalidLength
  }
  let mut out : Bytes = b""
  let mut block = 1
  while out.length() < dk_len {
    let counter = Bytes::makei(4, fn(i) {
      match i {
        0 => ((block >> 24) & 0xFF).to_byte()
        1 => ((block >> 16) & 0xFF).to_byte()
        2 => ((block >> 8) & 0xFF).to_byte()
        _ => (block & 0xFF).to_byte()
      }
    })
    let mut u = hmac_sm3(password, @byteutil.concat_bytes([salt, counter]))
    let t : FixedArray[Byte] = FixedArray::makei(u.length(), fn(i) { u[i] })
    for _ in 1..<iterations {
      u = hmac_sm3(password, u)
      for i = 0; i < t.length(); i = i + 1 {
        t[i] = (t[i].to_int() ^ u[i].to_int()).to_byte()
      }
    }
    out = @byteutil.concat_bytes([out, Bytes::from_array(t)])
    block = block + 1
  }
  out[:dk_len].to_owned()
}

///|
/// Derive a 32-byte key from `password` with PBKDF2-HMAC-SM3.
pub fn pbkdf2_hmac_sm3_32(
  password : Bytes,
  salt : Bytes,
  iterations : Int32,
) -> Bytes raise HmacError {
  pbkdf2_hmac_sm3(password, salt, iterations, 32)
}
