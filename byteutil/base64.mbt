/// Base64 (RFC 4648) encoding and decoding.
///
/// Only the standard +/ alphabet is supported; whitespace (spaces, CR, LF,
/// tabs) is ignored while decoding, so PEM bodies can be fed in directly.

///|
/// Standard base64 alphabet.
let base64_alphabet : FixedArray[Char] = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
]

///|
/// Build the reverse table. Called on each decode by `base64_decode_table()`;
/// keeping it a pure `fn` avoids depending on the evaluation order of
/// package-level `let` initialisers.
fn base64_decode_table() -> FixedArray[Byte] {
  let table : FixedArray[Byte] = FixedArray::make(256, b'\xff')
  for i = 0; i < 64; i = i + 1 {
    table[base64_alphabet[i].to_int()] = i.to_byte()
  }
  table
}

///|
/// Encode bytes as standard base64 with `=` padding (no line breaks).
pub fn base64_encode(data : Bytes) -> String {
  let n = data.length()
  let out_len = (n + 2) / 3 * 4
  let buf : FixedArray[Char] = FixedArray::make(out_len, '\u{0}')
  let mut i = 0
  let mut o = 0
  while i + 3 <= n {
    let b0 = data[i].to_int()
    let b1 = data[i + 1].to_int()
    let b2 = data[i + 2].to_int()
    buf[o] = base64_alphabet[(b0 >> 2) & 0x3F]
    buf[o + 1] = base64_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]
    buf[o + 2] = base64_alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)]
    buf[o + 3] = base64_alphabet[b2 & 0x3F]
    i = i + 3
    o = o + 4
  }
  let rem = n - i
  if rem == 1 {
    let b0 = data[i].to_int()
    buf[o] = base64_alphabet[(b0 >> 2) & 0x3F]
    buf[o + 1] = base64_alphabet[(b0 & 0x03) << 4]
    buf[o + 2] = '='
    buf[o + 3] = '='
  } else if rem == 2 {
    let b0 = data[i].to_int()
    let b1 = data[i + 1].to_int()
    buf[o] = base64_alphabet[(b0 >> 2) & 0x3F]
    buf[o + 1] = base64_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]
    buf[o + 2] = base64_alphabet[(b1 & 0x0F) << 2]
    buf[o + 3] = '='
  }
  let sb = StringBuilder()
  for c in buf {
    sb.write_char(c)
  }
  sb.to_string()
}

///|
/// Decode a standard base64 string.
///
/// Whitespace is ignored, so a PEM body can be fed in directly. Padding is
/// optional (`YWJjZA` and `YWJjZA==` both decode to `abcd`), matching Go's
/// `base64.StdEncoding` readers which accept unpadded input; when padding IS
/// present it must be complete and at the very end. Anything else — a
/// non-alphabet character, a `=` inside the data, more than two `=` — raises
/// `ByteUtilError::InvalidBase64`.
pub fn base64_decode(s : String) -> Bytes raise ByteUtilError {
  let n = s.length()
  // Six-bit values of the significant characters, -1 for `=`.
  let chars : Array[Int32] = []
  // Built once per call: a 256-entry table is cheap next to the decoding.
  let table = base64_decode_table()
  let mut pad = 0
  for i = 0; i < n; i = i + 1 {
    let c = s[i]
    let cu = c.to_int()
    if cu == 0x20 ||
      cu == 0x0A ||
      cu == 0x0D ||
      cu == 0x09 ||
      cu == 0x0B ||
      cu == 0x0C {
      continue
    }
    if c == '=' {
      pad = pad + 1
      chars.push(-1)
    } else if cu < 256 && table[cu] != b'\xff' {
      // Data after padding means the `=` was not at the end.
      if pad > 0 {
        raise ByteUtilError::InvalidBase64
      }
      chars.push(table[cu].to_int())
    } else {
      raise ByteUtilError::InvalidBase64
    }
  }
  let total = chars.length()
  if total == 0 {
    return Bytes::makei(0, fn(_) { b'\x00' })
  }
  if pad > 2 {
    raise ByteUtilError::InvalidBase64
  }
  // With padding the group count must be a multiple of 4 (and a single
  // trailing character is never legal); without padding a leftover of 1 six-
  // bit value cannot represent a whole byte.
  let groups = (total + 3) / 4
  if pad > 0 && total % 4 != 0 {
    raise ByteUtilError::InvalidBase64
  }
  if total % 4 == 1 {
    raise ByteUtilError::InvalidBase64
  }
  // Without padding the final group carries 2 or 3 significant characters;
  // everything past that is an artefact of rounding up to a whole group.
  let out_len = if pad > 0 {
    groups * 3 - pad
  } else {
    match total % 4 {
      2 => total / 4 * 3 + 1
      3 => total / 4 * 3 + 2
      _ => total / 4 * 3
    }
  }
  Bytes::makei(out_len, fn(i) {
    let q = i / 3
    let r = i % 3
    let c0 = chars[q * 4]
    // Missing characters (unpadded tail) decode as zero bits; the low bits of
    // the last value are unused, so any value there is discarded below.
    let c1 = if q * 4 + 1 < total { chars[q * 4 + 1] } else { 0 }
    let c2 = if q * 4 + 2 < total && chars[q * 4 + 2] > 0 {
      chars[q * 4 + 2]
    } else {
      0
    }
    let c3 = if q * 4 + 3 < total && chars[q * 4 + 3] > 0 {
      chars[q * 4 + 3]
    } else {
      0
    }
    let v = if r == 0 {
      (c0 << 2) | (c1 >> 4)
    } else if r == 1 {
      ((c1 & 0x0F) << 4) | (c2 >> 2)
    } else {
      ((c2 & 0x03) << 6) | c3
    }
    (v & 0xFF).to_byte()
  })
}
