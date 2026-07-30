/// PKCS#7 padding helpers used by SM4's ECB / CBC / CFB / OFB wrappers
/// (`sm4_ecb` / `sm4_cbc` / `sm4_cfb` / `sm4_ofb`). Defined in a dedicated
/// file so the padding logic can evolve independently of the rest of the
/// `byteutil` package and so the dedicated error type (`ByteUtilError`)
/// lives next to its only caller.

///|
pub enum ByteUtilError {
  InvalidPadding
} derive(Debug, Eq)

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
