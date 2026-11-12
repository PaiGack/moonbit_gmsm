/// ASN.1 DER encoding helpers and the `pad_left` helper used by
/// `normalize_32`. These functions are only used by the SM2 package
/// (`sign_digit_to_sign_data` / `sign_data_to_sign_digit` and the
/// `cipher_marshal` / `cipher_unmarshal` round-trip), so they live in a
/// dedicated file.

///|
/// Left-pad a byte sequence with zero bytes up to `target` length.
pub fn pad_left(data : Bytes, target : Int32) -> Bytes {
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
pub fn encode_asn1_length(len : Int32) -> Bytes {
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
/// Decode an ASN.1 length field starting at `off` and return
/// `(content_start, content_end, total_bytes_consumed)`, where
/// `content_end = content_start + length`.
///
/// This function never panics on untrusted input. Callers MUST still check
/// `content_end` against the end of the enclosing element (or the input
/// length) before slicing.
///
/// Strict checks:
/// - the length field itself must be fully present;
/// - indefinite length (`0x80`) and lengths spanning more than 4 bytes are
///   rejected (also prevents `Int` overflow while accumulating);
/// - long form must use minimal encoding (no leading zero byte, and the value
///   must not fit in the short form);
/// - the content must fit inside `data`.
pub fn decode_asn1_length(
  data : Bytes,
  off : Int32,
) -> (Int32, Int32, Int32) raise ByteUtilError {
  let size = data.length()
  if off < 0 || off >= size {
    raise ByteUtilError::InvalidDer
  }
  let first = data[off].to_uint()
  if first < 0x80U {
    // Callers check the content end against their own limit; the length field
    // itself only needs the tag byte to be present.
    return (off + 1, off + 1 + first.reinterpret_as_int(), 1)
  }
  let num_bytes = first.reinterpret_as_int() & 0x7F
  if num_bytes == 0 || num_bytes > 4 || off + 1 + num_bytes > size {
    raise ByteUtilError::InvalidDer
  }
  if data[off + 1] == b'\x00' {
    raise ByteUtilError::InvalidDer
  }
  let mut len : Int32 = 0
  for i in 0..<num_bytes {
    len = (len << 8) | data[off + 1 + i].to_int()
  }
  if len < 128 {
    raise ByteUtilError::InvalidDer
  }
  let content_start = off + 1 + num_bytes
  let end = content_start + len
  if end > size || end < content_start {
    raise ByteUtilError::InvalidDer
  }
  (content_start, end, 1 + num_bytes)
}

///|
/// Decode one complete TLV at `off`, bounded by `end_limit` (the end of the
/// enclosing element, or the input length at the top level). Returns
/// `(content_start, content_end, tag)`. Never reads outside `[off, end_limit)`
/// and never panics, so it is safe for untrusted input.
pub fn decode_asn1_tlv(
  data : Bytes,
  off : Int32,
  end_limit : Int32,
) -> (Int32, Int32, Int32) raise ByteUtilError {
  let size = data.length()
  if off < 0 || off + 1 >= size || off + 1 >= end_limit {
    raise ByteUtilError::InvalidDer
  }
  let tag = data[off].to_int()
  let (start, end, _) = decode_asn1_length(data, off + 1)
  if start > end_limit || end > end_limit {
    raise ByteUtilError::InvalidDer
  }
  (start, end, tag)
}

///|
/// Normalize a non-negative ASN.1 INTEGER content to exactly 32 bytes: strip
/// leading zero bytes (sign padding), then left-pad with zeros.
///
/// Raises `InvalidDer` for negative values (high bit set without a
/// leading `0x00`) and for values wider than 32 bytes.
pub fn normalize_32(data : Bytes) -> Bytes raise ByteUtilError {
  if data.length() == 0 {
    raise ByteUtilError::InvalidDer
  }
  // Negative ASN.1 INTEGER: two's complement with the sign bit set.
  if (data[0].to_uint() & 0x80U) != 0U {
    raise ByteUtilError::InvalidDer
  }
  let mut start = 0
  while start < data.length() && data[start] == b'\x00' {
    start = start + 1
  }
  if data.length() - start > 32 {
    raise ByteUtilError::InvalidDer
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
  // Content as written: a leading 0x00 when the high bit is set, then the
  // value bytes without their leading zeros.
  let content_len = if pad { remaining + 1 } else { remaining }
  let lb = encode_asn1_length(content_len)
  let total = 1 + lb.length() + content_len
  let content = Bytes::makei(content_len, fn(i) {
    if pad {
      if i == 0 {
        b'\x00'
      } else {
        bytes[start + i - 1]
      }
    } else {
      bytes[start + i]
    }
  })
  Bytes::makei(total, fn(i) {
    if i == 0 {
      b'\x02'
    } else if i < 1 + lb.length() {
      lb[i - 1]
    } else {
      content[i - 1 - lb.length()]
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
