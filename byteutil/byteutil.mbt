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

///|
pub enum ByteUtilError {
  InvalidPadding
} derive(Debug, Eq)

///|
/// Concatenate a list of byte segments into a single byte sequence.
pub fn concat_bytes(segments : Array[Bytes]) -> Bytes {
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
/// Encode an integer as 4-byte big-endian.
pub fn int_to_bytes_be(n : Int) -> Bytes {
  Bytes::from_array([
    ((n >> 24) & 0xFF).to_byte(),
    ((n >> 16) & 0xFF).to_byte(),
    ((n >> 8) & 0xFF).to_byte(),
    (n & 0xFF).to_byte(),
  ])
}

///|
/// XOR two equal-length byte sequences, returning a new byte sequence.
/// Aborts if the lengths differ.
pub fn xor_bytes(a : Bytes, b : Bytes) -> Bytes {
  if a.length() != b.length() {
    abort("xor_bytes: length mismatch")
  }
  Bytes::makei(a.length(), fn(i) { (a[i].to_uint() ^ b[i].to_uint()).to_byte() })
}

///|
/// PKCS#7 pad a byte sequence to a multiple of `block_size`.
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
/// Remove PKCS#7 padding. Returns `Err(ByteUtilError::InvalidPadding)` on
/// malformed padding so that callers can map it to their own error type.
pub fn pkcs7_unpad(data : Bytes) -> Result[Bytes, ByteUtilError] {
  if data.length() == 0 {
    return Err(ByteUtilError::InvalidPadding)
  }
  let pad_len = data[data.length() - 1].to_int()
  if pad_len < 1 || pad_len > 16 {
    return Err(ByteUtilError::InvalidPadding)
  }
  if pad_len > data.length() {
    return Err(ByteUtilError::InvalidPadding)
  }
  for i = data.length() - pad_len; i < data.length(); i = i + 1 {
    if data[i].to_int() != pad_len {
      return Err(ByteUtilError::InvalidPadding)
    }
  }
  Ok(data[0:data.length() - pad_len].to_owned())
}

///|
/// Left-pad a byte sequence with zero bytes up to `target` length.
pub fn pad_left(data : Bytes, target : Int) -> Bytes {
  if data.length() >= target {
    return data
  }
  Bytes::makei(target, fn(i) {
    let o = target - data.length()
    if i < o {
      b'\x00'
    } else {
      data[i - o]
    }
  })
}

///|
/// Encode an ASN.1 length field (definite, short or long form).
pub fn encode_asn1_length(len : Int) -> Bytes {
  if len < 128 {
    return Bytes::from_array([len.to_byte()])
  }
  let mut temp = len
  let mut byte_count = 0
  while temp > 0 {
    byte_count = byte_count + 1
    temp = temp >> 8
  }
  Bytes::makei(1 + byte_count, fn(i) {
    if i == 0 {
      (0x80 | byte_count).to_byte()
    } else {
      ((len >> ((byte_count - i) * 8)) & 0xFF).to_byte()
    }
  })
}

///|
/// Decode an ASN.1 length field starting at `off`.
/// Returns `(length, number_of_bytes_consumed)`.
pub fn decode_asn1_length(data : Bytes, off : Int) -> (Int, Int) {
  if off >= data.length() {
    abort("ASN.1: out of bounds")
  }
  let first = data[off].to_uint()
  if first < 0x80U {
    return (first.reinterpret_as_int(), 1)
  }
  let num_bytes = first.reinterpret_as_int() & 0x7F
  if num_bytes == 0 || off + 1 + num_bytes > data.length() {
    abort("ASN.1: invalid long length")
  }
  let mut len : Int = 0
  for i in 0..<num_bytes {
    len = (len << 8) | data[off + 1 + i].to_int()
  }
  (len, 1 + num_bytes)
}

///|
/// Normalize an ASN.1 INTEGER content to exactly 32 bytes: strip leading
/// zero bytes (sign padding), then left-pad with zeros.
pub fn normalize_32(data : Bytes) -> Bytes {
  let mut start = 0
  while start < data.length() - 1 &&
        data[start] == b'\x00' &&
        data.length() - start > 32 {
    start = start + 1
  }
  if data.length() - start > 32 {
    abort("integer too large")
  }
  pad_left(data[start:].to_owned(), 32)
}

///|
/// Encode an ASN.1 INTEGER (tag 0x02) from raw big-endian content.
pub fn encode_asn1_integer(bytes : Bytes) -> Bytes {
  let mut start = 0
  while start < bytes.length() && bytes[start] == b'\x00' {
    start = start + 1
  }
  let remaining = bytes.length() - start
  if remaining == 0 {
    return Bytes::from_array([b'\x02', b'\x01', b'\x00'])
  }
  let pad = (bytes[start].to_uint() & 0x80U) != 0U
  let content_len = if pad { remaining + 1 } else { remaining }
  let lb = encode_asn1_length(content_len)
  let total = 1 + lb.length() + content_len
  Bytes::makei(total, fn(i) {
    if i == 0 {
      b'\x02'
    } else if i < 1 + lb.length() {
      lb[i - 1]
    } else {
      let vi = i - 1 - lb.length()
      if pad {
        if vi == 0 {
          b'\x00'
        } else {
          bytes[start + vi - 1]
        }
      } else {
        bytes[start + vi]
      }
    }
  })
}

///|
/// Encode an ASN.1 OCTET STRING (tag 0x04).
pub fn encode_asn1_octet_string(data : Bytes) -> Bytes {
  let lb = encode_asn1_length(data.length())
  Bytes::makei(1 + lb.length() + data.length(), fn(i) {
    if i == 0 {
      b'\x04'
    } else if i < 1 + lb.length() {
      lb[i - 1]
    } else {
      data[i - 1 - lb.length()]
    }
  })
}
