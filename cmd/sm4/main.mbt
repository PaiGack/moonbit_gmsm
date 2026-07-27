//| SM4 demo (GM/T 0002-2012): single block, ECB and CBC modes with PKCS7
//| padding. Run with `moon run cmd/sm4`.

///|
fn nibble_to_char(n : Int) -> Char {
  if n < 10 {
    Int::unsafe_to_char(n + '0'.to_int())
  } else {
    Int::unsafe_to_char(n - 10 + 'a'.to_int())
  }
}

///|
fn byte_to_hex(b : Byte) -> String {
  let hi = (b.to_int() >> 4) & 0xF
  let lo = b.to_int() & 0xF
  nibble_to_char(hi).to_string() + nibble_to_char(lo).to_string()
}

///|
fn bytes_to_hex(b : Bytes) -> String {
  let buf = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    buf.write_string(byte_to_hex(b[i]))
  }
  buf.to_string()
}

///|
fn bytes_eq(a : Bytes, b : Bytes) -> Bool {
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
fn hex_nibble(c : UInt16) -> Int {
  if c >= 48 && c <= 57 {
    (c - 48).to_int()
  } else if c >= 65 && c <= 70 {
    (c - 65).to_int() + 10
  } else if c >= 97 && c <= 102 {
    (c - 97).to_int() + 10
  } else {
    abort("invalid hex char")
  }
}

///|
fn hex_to_bytes(s : String) -> Bytes {
  let len = s.length()
  if len % 2 != 0 {
    abort("hex string must have even length")
  }
  let n = len / 2
  Bytes::makei(n, fn(i) {
    let hi = hex_nibble(s[i * 2])
    let lo = hex_nibble(s[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn bstr(b : Bool) -> String {
  if b {
    "true"
  } else {
    "false"
  }
}

///|
fn main {
  try {
    println("========== SM4 Demo (GM/T 0002-2012) ==========")

    let key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
    let plain = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
    let iv = hex_to_bytes("00000000000000000000000000000000")

    // 1. Single block encryption (KAT from GM/T 0002-2012 Appendix A)
    let cipher = @gmsm_sm4.sm4_encrypt_block(key, plain)
    let expected = "681edf34d206965e86b3e94f536e4246"
    let got = bytes_to_hex(cipher)
    println(
      "Block encrypt : " +
      got +
      "  [" +
      (if got == expected { "OK" } else { "FAIL" }) +
      "]",
    )
    let dec = @gmsm_sm4.sm4_decrypt_block(key, cipher)
    println(
      "Block decrypt : " +
      bytes_to_hex(dec) +
      "  [" +
      (if bytes_eq(dec, plain) { "OK" } else { "FAIL" }) +
      "]",
    )

    // 2. ECB mode with PKCS7 padding (needs padded input length multiple of 16)
    let msg = b"Hello SM4 ECB mode demo."
    let padded = @gmsm_sm4.pkcs7_pad(msg, 16)
    let ecb_c = @gmsm_sm4.sm4_encrypt_ecb(key, padded)
    let ecb_d = @gmsm_sm4.pkcs7_unpad(@gmsm_sm4.sm4_decrypt_ecb(key, ecb_c))
    println("")
    println("ECB ciphertext: " + bytes_to_hex(ecb_c))
    println("ECB roundtrip : " + bstr(bytes_eq(ecb_d, msg)))

    // 3. CBC mode with PKCS7 padding
    let cbc_c = @gmsm_sm4.sm4_encrypt_cbc(key, iv, padded)
    let cbc_d = @gmsm_sm4.pkcs7_unpad(@gmsm_sm4.sm4_decrypt_cbc(key, iv, cbc_c))
    println("CBC ciphertext: " + bytes_to_hex(cbc_c))
    println("CBC roundtrip : " + bstr(bytes_eq(cbc_d, msg)))

    // 4. PKCS7 padding sanity
    let unpadded = @gmsm_sm4.pkcs7_unpad(@gmsm_sm4.pkcs7_pad(b"short", 16))
    println("PKCS7 roundtrip: " + bstr(bytes_eq(unpadded, b"short")))

    println("========== SM4 Demo Done ==========")
  } catch {
    _ => println("Error occurred during SM4 demo")
  }
}
