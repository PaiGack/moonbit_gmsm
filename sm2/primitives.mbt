/// SM2 Primitives: ZA, KDF, keXHat, msgHash helpers

///|
/// Default user ID (16 bytes), same as gmsm
fn default_uid_impl() -> Bytes {
  b"1234567812345678"
}

///|
// Curve constants as 32-byte strings
fn a_bytes() -> Bytes {
  @byteutil.bn_to_bytes(sm2_p256().a)
}

///|
fn b_bytes() -> Bytes {
  @byteutil.bn_to_bytes(sm2_p256().b)
}

///|
fn gx_bytes() -> Bytes {
  @byteutil.bn_to_bytes(sm2_p256().gx)
}

///|
fn gy_bytes() -> Bytes {
  @byteutil.bn_to_bytes(sm2_p256().gy)
}

///|
// Concatenate multiple Bytes segments into one
fn concat_bytes(segments : Array[Bytes]) -> Bytes {
  let mut total : Int = 0
  for i in 0..<segments.length() {
    total = total + segments[i].length()
  }
  Bytes::makei(total, fn(i) {
    let mut pos = i
    for j in 0..<segments.length() {
      let seg = segments[j]
      let seg_len = seg.length()
      if pos < seg_len {
        return seg[pos]
      }
      pos = pos - seg_len
    }
    abort("unreachable in concat_bytes")
  })
}

///|
/// Compute ZA = SM3(ENTLA ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA)
fn za(xA : FixedArray[UInt64], yA : FixedArray[UInt64], uid : Bytes) -> Bytes {
  if uid.length() >= 8192 {
    abort("Sm2Error::InvalidParameter: uid too long")
  }

  let entl = uid.length() * 8
  let entl_hi = ((entl >> 8) & 0xFF).to_byte()
  let entl_lo = (entl & 0xFF).to_byte()

  let xa_bytes = @byteutil.bn_to_bytes(xA)
  let ya_bytes = @byteutil.bn_to_bytes(yA)
  let a_b = a_bytes()
  let b_b = b_bytes()
  let gx_b = gx_bytes()
  let gy_b = gy_bytes()

  let partes : Array[Bytes] = [
    Bytes::from_array([entl_hi, entl_lo]),
    uid,
    a_b,
    b_b,
    gx_b,
    gy_b,
    xa_bytes,
    ya_bytes,
  ]
  let data = concat_bytes(partes)
  @sm3.sm3_sum(data)
}

///|
/// Compute message hash: SM3(ZA ‖ msg), returned as 256-bit integer
fn msg_hash(za_val : Bytes, msg : Bytes) -> FixedArray[UInt64] {
  let data = concat_bytes([za_val, msg])
  let hash = @sm3.sm3_sum(data)
  let e : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  @byteutil.bn_from_bytes(e, hash, 0)
  e
}

///|
/// KDF (Key Derivation Function)
fn kdf(length : Int, parts : Array[Bytes]) -> (Bytes, Bool) {
  if length == 0 {
    return (b"", true)
  }

  let z = concat_bytes(parts)
  let ct = (length + 31) / 32

  let mut all_zero = true
  let mut counter : Int = 1
  let chunks : Array[Bytes] = []

  for _ in 0..<ct {
    let cb = int_to_bytes_be(counter)
    let hash_input = concat_bytes([z, cb])
    let hash = @sm3.sm3_sum(hash_input)

    for j in 0..<32 {
      if hash[j] != b'\x00' {
        all_zero = false
      }
    }
    chunks.push(hash) |> ignore
    counter = counter + 1
  }

  if all_zero {
    return (b"", false)
  }

  let full = concat_bytes(chunks)
  let result = Bytes::makei(length, fn(i) { full[i] })
  (result, true)
}

///|
/// keXHat: set x = (x & (2^128 - 1)) | 2^127
fn ke_x_hat(x : FixedArray[UInt64]) -> FixedArray[UInt64] {
  let r : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_copy(r, x)
  r[2] = 0UL
  r[3] = 0UL
  r[1] = r[1] | (1UL << 63)
  r
}

///|
/// Convert int to 4-byte big-endian
fn int_to_bytes_be(n : Int) -> Bytes {
  Bytes::from_array([
    ((n >> 24) & 0xFF).to_byte(),
    ((n >> 16) & 0xFF).to_byte(),
    ((n >> 8) & 0xFF).to_byte(),
    (n & 0xFF).to_byte(),
  ])
}
