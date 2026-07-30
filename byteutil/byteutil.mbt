/// Shared low-level bit/byte helpers and byte <-> number conversion
/// utilities, reused by the `sm2`, `sm3`, `sm4` packages and the
/// command-line demos to avoid duplicating the same pure functions in each.
/// Hex encoding / decoding lives in `hexutil.mbt` of this package.

///|
/// 32-bit left rotation.
pub fn rotl(x : UInt, n : Int) -> UInt {
  let n = n % 32
  (x << n) | (x >> (32 - n))
}

///|
/// Read a 32-bit unsigned integer from `buf` at `offset` in big-endian byte
/// order.
pub fn get_u32_be(buf : Bytes, offset : Int) -> UInt {
  (buf[offset].to_uint().land(0xffU) << 24) |
  (buf[offset + 1].to_uint().land(0xffU) << 16) |
  (buf[offset + 2].to_uint().land(0xffU) << 8) |
  buf[offset + 3].to_uint().land(0xffU)
}

///|
/// Read a 64-bit unsigned integer from `buf` at `offset` in big-endian byte
/// order.
pub fn get_u64_be(buf : Bytes, offset : Int) -> UInt64 {
  (buf[offset].to_uint64() << 56) |
  (buf[offset + 1].to_uint64() << 48) |
  (buf[offset + 2].to_uint64() << 40) |
  (buf[offset + 3].to_uint64() << 32) |
  (buf[offset + 4].to_uint64() << 24) |
  (buf[offset + 5].to_uint64() << 16) |
  (buf[offset + 6].to_uint64() << 8) |
  buf[offset + 7].to_uint64()
}

///|
/// Read a 32-bit unsigned integer from a `FixedArray[Byte]` at `offset` in
/// big-endian byte order. This is the `FixedArray[Byte]` counterpart of
/// `get_u32_be`.
pub fn get_u32_be_fa(buf : FixedArray[Byte], offset : Int) -> UInt {
  (buf[offset].to_uint().land(0xffU) << 24) |
  (buf[offset + 1].to_uint().land(0xffU) << 16) |
  (buf[offset + 2].to_uint().land(0xffU) << 8) |
  buf[offset + 3].to_uint().land(0xffU)
}

///|
/// Convert 32 bytes (big-endian) to 4 × 64-bit limbs (little-endian).
pub fn bn_from_bytes(r : FixedArray[UInt64], b : Bytes, off : Int) -> Unit {
  r[0] = get_u64_be(b, off + 24)
  r[1] = get_u64_be(b, off + 16)
  r[2] = get_u64_be(b, off + 8)
  r[3] = get_u64_be(b, off)
}

///|
/// Convert 4 × 64-bit limbs to 32 bytes (big-endian).
pub fn bn_to_bytes(r : FixedArray[UInt64]) -> Bytes {
  Bytes::makei(32, fn(i) {
    let limb = r[3 - i / 8]
    let shift = 56 - i % 8 * 8
    ((limb >> shift) & 0xFFUL).to_byte()
  })
}

///|
/// Convert a 16-byte block into 4 big-endian 32-bit words.
pub fn block_to_words(b : Bytes) -> FixedArray[UInt] {
  FixedArray::makei(4, fn(i) { get_u32_be(b, i * 4) })
}

///|
/// Convert 4 big-endian 32-bit words back into a 16-byte block.
pub fn words_to_block(w : FixedArray[UInt]) -> Bytes {
  Bytes::makei(16, fn(i) {
    let word = w[i / 4]
    let shift = 24 - i % 4 * 8
    ((word >> shift) & 0xFFU).to_byte()
  })
}

///|
pub fn bytes_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
pub fn bstr(b : Bool) -> String {
  if b {
    "true"
  } else {
    "false"
  }
}
