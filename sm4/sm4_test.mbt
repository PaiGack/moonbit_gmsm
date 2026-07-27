/// SM4 public API tests (blackbox).

///|
/// Helper to convert hex string to bytes.
fn hex_to_bytes(s : String) -> Bytes {
  let len = s.length()
  if len % 2 != 0 { abort("hex string must have even length") }
  let n = len / 2
  Bytes::makei(n, fn(i) {
    let hi = hex_nibble(s[i * 2])
    let lo = hex_nibble(s[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

fn hex_nibble(c : Char) -> Int {
  match c {
    '0' => 0; '1' => 1; '2' => 2; '3' => 3; '4' => 4; '5' => 5; '6' => 6; '7' => 7
    '8' => 8; '9' => 9
    'A' | 'a' => 10; 'B' | 'b' => 11; 'C' | 'c' => 12; 'D' | 'd' => 13; 'E' | 'e' => 14
    'F' | 'f' => 15
    _ => abort("invalid hex char")
  }
}

/// GM/T 0002-2012 Appendix A: standard test vector
let KAT_key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
let KAT_plain = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
// Known ciphertext from GM/T 0002-2012 Appendix A
let KAT_cipher = hex_to_bytes("681EDF34D206965E86B3E94F536E4246")

/// Single block encryption KAT from GM/T 0002-2012 Appendix A.
test "sm4_encrypt_block_kat" {
  let cipher = @sm4.sm4_encrypt_block(KAT_key, KAT_plain)
  for i = 0; i < 16; i = i + 1 {
    assert_eq!(cipher[i], KAT_cipher[i])
  }
}

/// Single block decryption KAT.
test "sm4_decrypt_block_kat" {
  let plain = @sm4.sm4_decrypt_block(KAT_key, KAT_cipher)
  for i = 0; i < 16; i = i + 1 {
    assert_eq!(plain[i], KAT_plain[i])
  }
}

/// Single block encrypt/decrypt round-trip with random data.
test "sm4_block_roundtrip" {
  let key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
  // Test 100 random blocks
  for seed = 0; seed < 100; seed = seed + 1 {
    let data = Bytes::makei(16, fn(i) {
      let v = ((seed * 256 + i * 17 + 42) & 0xFF)
      v.to_byte()
    })
    let cipher = @sm4.sm4_encrypt_block(key, data)
    let plain = @sm4.sm4_decrypt_block(key, cipher)
    for i = 0; i < 16; i = i + 1 {
      assert_eq!(plain[i], data[i])
    }
  }
}

/// ECB encrypt/decrypt round-trip.
test "sm4_ecb_roundtrip" {
  let key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
  let data = Bytes::makei(32, fn(i) { (i & 0xFF).to_byte() })
  let cipher = @sm4.sm4_encrypt_ecb(key, data)
  let plain = @sm4.sm4_decrypt_ecb(key, cipher)
  for i = 0; i < 32; i = i + 1 {
    assert_eq!(plain[i], data[i])
  }
}

/// ECB encrypt/decrypt round-trip with multiple blocks.
test "sm4_ecb_roundtrip_multiple_blocks" {
  let key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
  let data = Bytes::makei(48, fn(i) { ((i * 7 + 13) & 0xFF).to_byte() })
  let cipher = @sm4.sm4_encrypt_ecb(key, data)
  let plain = @sm4.sm4_decrypt_ecb(key, cipher)
  for i = 0; i < 48; i = i + 1 {
    assert_eq!(plain[i], data[i])
  }
}

/// CBC encrypt/decrypt round-trip.
test "sm4_cbc_roundtrip" {
  let key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
  let iv = hex_to_bytes("00000000000000000000000000000000")
  let data = Bytes::makei(32, fn(i) { ((i + 1) & 0xFF).to_byte() })
  let cipher = @sm4.sm4_encrypt_cbc(key, iv, data)
  let plain = @sm4.sm4_decrypt_cbc(key, iv, cipher)
  for i = 0; i < 32; i = i + 1 {
    assert_eq!(plain[i], data[i])
  }
}

/// CBC encrypt/decrypt round-trip with multi-block data.
test "sm4_cbc_roundtrip_multiple_blocks" {
  let key = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
  let iv = hex_to_bytes("00000000000000000000000000000000")
  let data = Bytes::makei(48, fn(i) { ((i * 3 + 7) & 0xFF).to_byte() })
  let cipher = @sm4.sm4_encrypt_cbc(key, iv, data)
  let plain = @sm4.sm4_decrypt_cbc(key, iv, cipher)
  for i = 0; i < 48; i = i + 1 {
    assert_eq!(plain[i], data[i])
  }
}

/// CBC round-trip with single block and different key/IV.
test "sm4_cbc_roundtrip_single_block" {
  let key = hex_to_bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
  let iv = hex_to_bytes("ABCDEF0123456789ABCDEF0123456789")
  let data = hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
  let cipher = @sm4.sm4_encrypt_cbc(key, iv, data)
  let plain = @sm4.sm4_decrypt_cbc(key, iv, cipher)
  for i = 0; i < 16; i = i + 1 {
    assert_eq!(plain[i], data[i])
  }
}

/// PKCS7 pad / unpad round-trip.
test "pkcs7_pad_unpad_roundtrip" {
  let data = b"hello"
  let padded = @sm4.pkcs7_pad(data, 16)
  assert_eq!(padded.length(), 16)
  let unpadded = @sm4.pkcs7_unpad(padded)
  assert_eq!(unpadded.length(), 5)
  for i = 0; i < 5; i = i + 1 {
    assert_eq!(unpadded[i], data[i])
  }
}

/// PKCS7 padding with exact block size produces a full block of padding.
test "pkcs7_pad_exact_block" {
  let data = b"1234567890123456" // exactly 16 bytes
  let padded = @sm4.pkcs7_pad(data, 16)
  assert_eq!(padded.length(), 32)
  // Last 16 bytes should be 0x10
  for i = 16; i < 32; i = i + 1 {
    assert_eq!(padded[i], b'\x10')
  }
}

/// PKCS7 unpadding empty padding block returns empty.
test "pkcs7_unpad_full_block" {
  let padded = Bytes::makei(16, fn(_i) { b'\x10' })
  let unpadded = @sm4.pkcs7_unpad(padded)
  assert_eq!(unpadded.length(), 0)
}

/// PKCS7 pad empty data.
test "pkcs7_pad_empty" {
  let padded = @sm4.pkcs7_pad(b"", 16)
  assert_eq!(padded.length(), 16)
  for i = 0; i < 16; i = i + 1 {
    assert_eq!(padded[i], b'\x10')
  }
}

/// PKCS7 pad with various block sizes.
test "pkcs7_pad_different_block_sizes" {
  // block_size 16: pad "AB" (2 bytes) -> 14 bytes of 0x0E
  let data = b"AB"
  let padded = @sm4.pkcs7_pad(data, 16)
  assert_eq!(padded.length(), 16)
  assert_eq!(padded[0], b'A')
  assert_eq!(padded[1], b'B')
  for i = 2; i < 16; i = i + 1 {
    assert_eq!(padded[i], b'\x0E')
  }
}
