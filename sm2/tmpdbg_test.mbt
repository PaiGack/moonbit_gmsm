///|
test "tmpdbg" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"asn1 test"
  let der = @sm2.sm2_encrypt_asn1(public_key, msg, @sm2.os_rand())
  println(@byteutil.bytes_to_hex(der))
  let back = @byteutil.bytes_to_hex(@sm2.cipher_unmarshal(der))
  println(back)
  println(
    @byteutil.bytes_to_hex(@sm2.cipher_marshal(@byteutil.hex_to_bytes(back))),
  )
  println(@sm2.sm2_decrypt_asn1(private_key, der).length().to_string())
}
