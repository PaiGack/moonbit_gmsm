/// ASN.1 DER encoding helpers and the `pad_left` helper used by
/// `normalize_32`. These functions are only used by the SM2 package
/// (`sign_digit_to_sign_data` / `sign_data_to_sign_digit` and the
/// `cipher_marshal` / `cipher_unmarshal` round-trip), so they live in a
/// dedicated file.

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
