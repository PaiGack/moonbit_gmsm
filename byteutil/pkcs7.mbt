/// PKCS#7 padding helpers used by SM4's ECB / CBC / CFB / OFB wrappers
/// (`sm4_ecb` / `sm4_cbc` / `sm4_cfb` / `sm4_ofb`). Defined in a dedicated
/// file so the padding logic can evolve independently of the rest of the
/// `byteutil` package and so the dedicated error type (`ByteUtilError`)
/// lives next to its only caller.

///|
#derive(Debug, Eq)
pub suberror ByteUtilError {
  InvalidPadding
  InvalidBase64
  // PEM: more than one block where exactly one was expected / bad header
  InvalidLength
}

///|
/// PKCS#7 pad a byte sequence to a multiple of `block_size`.
pub fn pkcs7_pad(data : Bytes, block_size : Int32) -> Bytes {
  let pad_len = block_size - data.length() % block_size
  Bytes::makei(data.length() + pad_len, fn(i) {
    if i < data.length() {
      data[i]
    } else {
      // `pad_len` is in 1..block_size; for block_size = 16 it can exceed
      // 0x7f's low nibble patterns only via 16 == 0x10, so keep the value as
      // an Int and convert through a literal table to stay off any
      // `.to_byte()` edge cases.
      byte_of_pad_len(pad_len)
    }
  })
}

///|
/// Byte value of a PKCS#7 pad length (up to 16).
fn byte_of_pad_len(n : Int32) -> Byte {
  n.to_byte()
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
pub extend ByteUtilError with @debug.Debug::{to_repr}

///|
pub extend ByteUtilError with Eq::{not_equal, equal}
