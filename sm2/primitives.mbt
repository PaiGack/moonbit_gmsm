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
/// Compute ZA = SM3(ENTLA ‖ uid ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA).
///
/// Public counterpart of `sm2.ZA(pub, uid)`; see `SM2PublicKey::za`.
///
/// Raises `InvalidParameter` when `uid` is 8192 bytes or longer, so ENTLA no
/// longer fits in 16 bits. This is the same error model as
/// `SM2PublicKey::za` — callers such as `sm2_sign` / `sm2_verify` /
/// `key_exchange_*` therefore report a bad `uid` as a plain `Sm2Error`
/// instead of aborting the process.
fn za(
  xA : FixedArray[UInt64],
  yA : FixedArray[UInt64],
  uid : Bytes,
) -> Bytes raise Sm2Error {
  if uid.length() >= 8192 {
    raise Sm2Error::InvalidParameter
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
  let data = @byteutil.concat_bytes(partes)
  @sm3.sm3_sum(data)
}

///|
/// Compute message hash: SM3(ZA ‖ msg), returned as 256-bit integer
fn msg_hash(za_val : Bytes, msg : Bytes) -> FixedArray[UInt64] {
  let data = @byteutil.concat_bytes([za_val, msg])
  let hash = @sm3.sm3_sum(data)
  let e : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  @byteutil.bn_from_bytes(e, hash, 0)
  e
}

///|
/// KDF (Key Derivation Function)
fn kdf(length : Int32, parts : Array[Bytes]) -> (Bytes, Bool) {
  if length == 0 {
    return (b"", true)
  }

  let z = @byteutil.concat_bytes(parts)
  let ct = (length + 31) / 32

  let mut all_zero = true
  let mut counter : Int32 = 1
  let chunks : Array[Bytes] = []

  for _ in 0..<ct {
    let cb = @byteutil.int_to_bytes_be(counter)
    let hash_input = @byteutil.concat_bytes([z, cb])
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

  let full = @byteutil.concat_bytes(chunks)
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
