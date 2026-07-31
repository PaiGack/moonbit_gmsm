//| SM2 demo (GM/T 0003-2012): key generation, signature, encryption,
//| point compression and key exchange. Run with `moon run cmd/sm2`.

///|
fn main {
  try {
    println("========== SM2 Demo (GM/T 0003-2012) ==========")

    // 1. Key generation
    let pri = @gmsm_sm2.generate_key(None)
    let pubk = @gmsm_sm2.derive_public_key(pri)
    println(
      "Private key d : " + @byteutil.bytes_to_hex(@byteutil.bn_to_bytes(pri.d)),
    )
    println(
      "Public key  X : " + @byteutil.bytes_to_hex(@byteutil.bn_to_bytes(pubk.x)),
    )
    println(
      "Public key  Y : " + @byteutil.bytes_to_hex(@byteutil.bn_to_bytes(pubk.y)),
    )
    println("Point on curve: " + @byteutil.bstr(@gmsm_sm2.is_on_curve(pubk)))

    // 2. Signature / verify
    let uid = @gmsm_sm2.default_uid()
    let msg = b"Hello SM2! This is a demo."
    let (r, s) = @gmsm_sm2.sm2_sign(pri, msg, uid, None)
    let verified = @gmsm_sm2.sm2_verify(pubk, msg, uid, r, s)
    println("")
    println("Signature r   : " + @byteutil.bytes_to_hex(r))
    println("Signature s   : " + @byteutil.bytes_to_hex(s))
    println("Verify        : " + @byteutil.bstr(verified))

    // 3. ASN.1 DER signature
    let der = @gmsm_sm2.sm2_sign_der(pri, msg, uid, None)
    let der_ok = @gmsm_sm2.sm2_verify_der(pubk, msg, uid, der)
    println("DER sign len  : " + der.length().to_string())
    println("DER verify    : " + @byteutil.bstr(der_ok))

    // 4. Encrypt / decrypt (C1C2C3 mode)
    let plain = b"Secret message over SM2."
    let cipher = @gmsm_sm2.sm2_encrypt(pubk, plain, None, @gmsm_sm2.C1C2C3)
    let dec = @gmsm_sm2.sm2_decrypt(pri, cipher, @gmsm_sm2.C1C2C3)
    println("")
    println("Cipher(C1C2C3): " + @byteutil.bytes_to_hex(cipher))
    println("Decrypted     : " + dec.to_string())
    println("Decrypt OK    : " + @byteutil.bstr(@byteutil.bytes_eq(dec, plain)))

    // 5. ASN.1 (C1C3C2) marshal / unmarshal
    let der_cipher = @gmsm_sm2.sm2_encrypt_asn1(pubk, plain, None)
    let der_dec = @gmsm_sm2.sm2_decrypt_asn1(pri, der_cipher)
    println(
      "ASN.1 decrypt OK: " + @byteutil.bstr(@byteutil.bytes_eq(der_dec, plain)),
    )

    // 6. Point compression / decompression
    let comp = @gmsm_sm2.compress_point(pubk)
    let decomp = @gmsm_sm2.decompress_point(comp)
    println("")
    println("Compressed    : " + @byteutil.bytes_to_hex(comp))
    println(
      "Decompress on curve: " + @byteutil.bstr(@gmsm_sm2.is_on_curve(decomp)),
    )

    // 7. Key exchange (A and B derive the same shared key)
    let rpriA = @gmsm_sm2.generate_key(None)
    let rpubA = @gmsm_sm2.derive_public_key(rpriA)
    let privB = @gmsm_sm2.generate_key(None)
    let pubB = @gmsm_sm2.derive_public_key(privB)
    let rprivB = @gmsm_sm2.generate_key(None)
    let rpubB = @gmsm_sm2.derive_public_key(rprivB)
    let ida = b"alice1234567890"
    let idb = b"bob1234567890"
    let (ka, _, _) = @gmsm_sm2.key_exchange_a(
      16, ida, idb, pri, pubB, rpriA, rpubB,
    )
    let (kb, _, _) = @gmsm_sm2.key_exchange_b(
      16, ida, idb, privB, pubk, rprivB, rpubA,
    )
    println("")
    println(
      "Key exchange equal : " + @byteutil.bstr(@byteutil.bytes_eq(ka, kb)),
    )
    println("Shared key (hex)   : " + @byteutil.bytes_to_hex(ka))

    println("========== SM2 Demo Done ==========")
  } catch {
    _ => println("Error occurred during SM2 demo")
  }
}
