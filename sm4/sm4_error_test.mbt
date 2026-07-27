/// SM4 error-branch tests (blackbox): each public function raises the
/// documented `SM4Error` on invalid input.

///|
fn expect_err(tag : String, r : Result[Unit, SM4Error]) -> Unit {
  match r {
    Ok(_) => abort("expected error in " + tag)
    Err(_) => ()
  }
}

///|
test "sm4_encrypt_block_invalid_key" {
  let key = Bytes::makei(15, fn(i) { i.to_byte() }) // wrong length
  let data = Bytes::makei(16, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_encrypt_block(key, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("encrypt_block key", r)
}

///|
test "sm4_encrypt_block_invalid_data" {
  let key = Bytes::makei(16, fn(i) { i.to_byte() })
  let data = Bytes::makei(15, fn(_) { b'\x00' }) // wrong length
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_encrypt_block(key, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("encrypt_block data", r)
}

///|
test "sm4_decrypt_block_invalid_key" {
  let key = Bytes::makei(15, fn(i) { i.to_byte() })
  let data = Bytes::makei(16, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_decrypt_block(key, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("decrypt_block key", r)
}

///|
test "sm4_decrypt_block_invalid_data" {
  let key = Bytes::makei(16, fn(i) { i.to_byte() })
  let data = Bytes::makei(15, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_decrypt_block(key, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("decrypt_block data", r)
}

///|
test "sm4_encrypt_ecb_invalid_key" {
  let key = Bytes::makei(15, fn(i) { i.to_byte() })
  let data = Bytes::makei(32, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_encrypt_ecb(key, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("encrypt_ecb key", r)
}

///|
test "sm4_encrypt_ecb_invalid_data" {
  let key = Bytes::makei(16, fn(i) { i.to_byte() })
  let data = Bytes::makei(31, fn(_) { b'\x00' }) // not multiple of 16
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_encrypt_ecb(key, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("encrypt_ecb data", r)
}

///|
test "sm4_decrypt_ecb_invalid_key" {
  let key = Bytes::makei(15, fn(i) { i.to_byte() })
  let data = Bytes::makei(32, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_decrypt_ecb(key, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("decrypt_ecb key", r)
}

///|
test "sm4_decrypt_ecb_invalid_data" {
  let key = Bytes::makei(16, fn(i) { i.to_byte() })
  let data = Bytes::makei(31, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_decrypt_ecb(key, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("decrypt_ecb data", r)
}

///|
test "sm4_encrypt_cbc_invalid_key" {
  let key = Bytes::makei(15, fn(i) { i.to_byte() })
  let iv = Bytes::makei(16, fn(_) { b'\x00' })
  let data = Bytes::makei(32, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_encrypt_cbc(key, iv, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("encrypt_cbc key", r)
}

///|
test "sm4_encrypt_cbc_invalid_iv" {
  let key = Bytes::makei(16, fn(i) { i.to_byte() })
  let iv = Bytes::makei(15, fn(_) { b'\x00' }) // wrong length
  let data = Bytes::makei(32, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_encrypt_cbc(key, iv, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("encrypt_cbc iv", r)
}

///|
test "sm4_encrypt_cbc_invalid_data" {
  let key = Bytes::makei(16, fn(i) { i.to_byte() })
  let iv = Bytes::makei(16, fn(_) { b'\x00' })
  let data = Bytes::makei(31, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_encrypt_cbc(key, iv, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("encrypt_cbc data", r)
}

///|
test "sm4_decrypt_cbc_invalid_key" {
  let key = Bytes::makei(15, fn(i) { i.to_byte() })
  let iv = Bytes::makei(16, fn(_) { b'\x00' })
  let data = Bytes::makei(32, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_decrypt_cbc(key, iv, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("decrypt_cbc key", r)
}

///|
test "sm4_decrypt_cbc_invalid_iv" {
  let key = Bytes::makei(16, fn(i) { i.to_byte() })
  let iv = Bytes::makei(15, fn(_) { b'\x00' })
  let data = Bytes::makei(32, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_decrypt_cbc(key, iv, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("decrypt_cbc iv", r)
}

///|
test "sm4_decrypt_cbc_invalid_data" {
  let key = Bytes::makei(16, fn(i) { i.to_byte() })
  let iv = Bytes::makei(16, fn(_) { b'\x00' })
  let data = Bytes::makei(31, fn(_) { b'\x00' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.sm4_decrypt_cbc(key, iv, data))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("decrypt_cbc data", r)
}

///|
test "pkcs7_unpad_empty" {
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.pkcs7_unpad(b""))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("unpad empty", r)
}

///|
test "pkcs7_unpad_invalid_pad_value" {
  // last byte 0x11 (17) > 16 -> invalid
  let bad = Bytes::makei(16, fn(i) { if i == 15 { b'\x11' } else { b'\x01' } })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.pkcs7_unpad(bad))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("unpad pad value", r)
}

///|
test "pkcs7_unpad_pad_too_long" {
  // last byte 0x10 (16) but only 1 byte total -> pad_len > length
  let bad = Bytes::makei(1, fn(_) { b'\x10' })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.pkcs7_unpad(bad))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("unpad too long", r)
}

///|
test "pkcs7_unpad_wrong_pad_bytes" {
  // claims 3 bytes of padding 0x03 but data is only 4 bytes long,
  // so pad_len (3) would exceed length -> rejected first.
  let bad = Bytes::makei(4, fn(i) {
    match i {
      0 => b'A'
      1 => b'B'
      2 => b'\x03'
      3 => b'\x03'
      _ => b'\x00'
    }
  })
  let r : Result[Unit, SM4Error] = try {
    ignore(@sm4.pkcs7_unpad(bad))
    Ok(())
  } catch {
    e => Err(e)
  }
  expect_err("unpad wrong bytes", r)
}

///|
test "sm4_error_decrypt_failed_constructible" {
  let e = @sm4.sm4_error_decrypt_failed()
  match e {
    SM4Error::DecryptFailed => ()
    _ => abort("expected DecryptFailed")
  }
}
