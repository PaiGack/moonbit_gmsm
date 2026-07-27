//| SM4 demo (GM/T 0002-2012): single block, ECB and CBC modes with PKCS7
//| padding. Run with `moon run cmd/sm4`.

///|
fn main {
  try {
    println("========== SM4 Demo (GM/T 0002-2012) ==========")

    let key = @hexutil.hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
    let plain = @hexutil.hex_to_bytes("0123456789ABCDEFFEDCBA9876543210")
    let iv = @hexutil.hex_to_bytes("00000000000000000000000000000000")

    // 1. Single block encryption (KAT from GM/T 0002-2012 Appendix A)
    let cipher = @gmsm_sm4.sm4_encrypt_block(key, plain)
    let expected = "681edf34d206965e86b3e94f536e4246"
    let got = @hexutil.bytes_to_hex(cipher)
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
      @hexutil.bytes_to_hex(dec) +
      "  [" +
      (if @hexutil.bytes_eq(dec, plain) { "OK" } else { "FAIL" }) +
      "]",
    )

    // 2. ECB mode with PKCS7 padding (needs padded input length multiple of 16)
    let msg = b"Hello SM4 ECB mode demo."
    let padded = @gmsm_sm4.pkcs7_pad(msg, 16)
    let ecb_c = @gmsm_sm4.sm4_encrypt_ecb(key, padded)
    let ecb_d = @gmsm_sm4.pkcs7_unpad(@gmsm_sm4.sm4_decrypt_ecb(key, ecb_c))
    println("")
    println("ECB ciphertext: " + @hexutil.bytes_to_hex(ecb_c))
    println("ECB roundtrip : " + @hexutil.bstr(@hexutil.bytes_eq(ecb_d, msg)))

    // 3. CBC mode with PKCS7 padding
    let cbc_c = @gmsm_sm4.sm4_encrypt_cbc(key, iv, padded)
    let cbc_d = @gmsm_sm4.pkcs7_unpad(@gmsm_sm4.sm4_decrypt_cbc(key, iv, cbc_c))
    println("CBC ciphertext: " + @hexutil.bytes_to_hex(cbc_c))
    println("CBC roundtrip : " + @hexutil.bstr(@hexutil.bytes_eq(cbc_d, msg)))

    // 4. PKCS7 padding sanity
    let unpadded = @gmsm_sm4.pkcs7_unpad(@gmsm_sm4.pkcs7_pad(b"short", 16))
    println(
      "PKCS7 roundtrip: " + @hexutil.bstr(@hexutil.bytes_eq(unpadded, b"short")),
    )

    println("========== SM4 Demo Done ==========")
  } catch {
    _ => println("Error occurred during SM4 demo")
  }
}
