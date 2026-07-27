/// SM2 Primitives: ZA, KDF, keXHat, msgHash helpers

///|
/// Default user ID (16 bytes), same as gmsm
fn default_uid_impl() -> Bytes {
  b"1234567812345678"
}

///|
// Curve constants as 32-byte strings
fn a_bytes() -> Bytes {
  bn_to_bytes(
    FixedArray::makei(4, fn(i) {
      match i {
        0 => 0xFFFFFFFFFFFFFFFCUL
        1 => 0xFFFFFFFF00000000UL
        2 => 0xFFFFFFFFFFFFFFFFUL
        3 => 0xFFFFFFFEFFFFFFFFUL
        _ => abort("unreachable")
      }
    }),
  )
}

///|
fn b_bytes() -> Bytes {
  bn_to_bytes(
    FixedArray::makei(4, fn(i) {
      match i {
        0 => 0xDDBCBD414D940E93UL
        1 => 0xF39789F515AB8F92UL
        2 => 0x4D5A9E4BCF6509A7UL
        3 => 0x28E9FA9E9D9F5E34UL
        _ => abort("unreachable")
      }
    }),
  )
}

///|
fn gx_bytes() -> Bytes {
  bn_to_bytes(
    FixedArray::makei(4, fn(i) {
      match i {
        0 => 0x715A4589334C74C7UL
        1 => 0x8FE30BBFF2660BE1UL
        2 => 0x5F9904466A39C994UL
        3 => 0x32C4AE2C1F198119UL
        _ => abort("unreachable")
      }
    }),
  )
}

///|
fn gy_bytes() -> Bytes {
  bn_to_bytes(
    FixedArray::makei(4, fn(i) {
      match i {
        0 => 0x02DF32E52139F0A0UL
        1 => 0xD0A9877CC62A4740UL
        2 => 0x59BDCEE36B692153UL
        3 => 0xBC3736A2F4F6779CUL
        _ => abort("unreachable")
      }
    }),
  )
}

///|
// Concatenate multiple Bytes segments into one
fn concat_bytes(segments : Array[Bytes]) -> Bytes {
  let mut total : Int = 0
  for i = 0; i < segments.length(); i = i + 1 {
    total = total + segments[i].length()
  }
  Bytes::makei(total, fn(i) {
    let mut pos = i
    for j = 0; j < segments.length(); j = j + 1 {
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
pub fn za(
  xA : FixedArray[UInt64],
  yA : FixedArray[UInt64],
  uid : Bytes,
) -> Bytes {
  if uid.length() >= 8192 {
    abort("Sm2Error::InvalidParameter: uid too long")
  }

  let entl = uid.length() * 8
  let entl_hi = ((entl >> 8) & 0xFF).to_byte()
  let entl_lo = (entl & 0xFF).to_byte()

  let xa_bytes = bn_to_bytes(xA)
  let ya_bytes = bn_to_bytes(yA)
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
pub fn msg_hash(za_val : Bytes, msg : Bytes) -> FixedArray[UInt64] {
  let data = concat_bytes([za_val, msg])
  let hash = @sm3.sm3_sum(data)
  let e : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_from_bytes(e, hash, 0)
  e
}

///|
/// KDF (Key Derivation Function)
pub fn kdf(length : Int, parts : Array[Bytes]) -> (Bytes, Bool) {
  if length == 0 {
    return (b"", true)
  }

  let z = concat_bytes(parts)
  let ct = (length + 31) / 32

  let mut all_zero = true
  let mut counter : Int = 1
  let chunks : Array[Bytes] = []

  for i = 0; i < ct; i = i + 1 {
    let cb = int_to_bytes_be(counter)
    let hash_input = concat_bytes([z, cb])
    let hash = @sm3.sm3_sum(hash_input)

    for j = 0; j < 32; j = j + 1 {
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
pub fn ke_x_hat(x : FixedArray[UInt64]) -> FixedArray[UInt64] {
  let r : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_copy(r, x)
  r[2] = 0UL
  r[3] = 0UL
  r[1] = r[1] | (1UL << 63)
  r
}

///|
/// Convert int to 4-byte big-endian
pub fn int_to_bytes_be(n : Int) -> Bytes {
  Bytes::from_array([
    ((n >> 24) & 0xFF).to_byte(),
    ((n >> 16) & 0xFF).to_byte(),
    ((n >> 8) & 0xFF).to_byte(),
    (n & 0xFF).to_byte(),
  ])
}
