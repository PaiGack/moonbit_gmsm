/// SM3 whitebox tests (package-internal).
/// These run in the same compilation unit as `sm3.mbt`, which makes the
/// library source eligible for coverage instrumentation (blackbox `_test`
/// files import the package as an external dependency and are not instrumented).

///|
/// Internal helper coverage: `rotl` wraps around the 32-bit boundary.
test "wb_rotl" {
  assert_eq(@byteutil.rotl(0x80000000U, 1), 0x00000001U)
  assert_eq(@byteutil.rotl(0x00000001U, 31), 0x80000000U)
}

///|
/// `tj` selects the correct constant for the two round ranges.
test "wb_tj" {
  assert_eq(tj(0), 0x79cc4519U)
  assert_eq(tj(16), 0x7a879d8aU)
}

///|
/// `ff`/`gg` boolean functions branch on `j`, and `p0`/`p1` permutations.
test "wb_ff_gg_p0_p1" {
  assert_eq(ff(0, 1U, 2U, 4U), 1U ^ 2U ^ 4U)
  assert_eq(gg(0, 1U, 2U, 4U), 1U ^ 2U ^ 4U)
  assert_eq(ff(16, 1U, 2U, 4U), (1U & 2U) | (1U & 4U) | (2U & 4U))
  assert_eq(gg(16, 1U, 2U, 4U), (1U & 2U) | (1U.lnot() & 4U))
  let x = 0x12345678U
  assert_eq(p0(x), x ^ @byteutil.rotl(x, 9) ^ @byteutil.rotl(x, 17))
  assert_eq(p1(x), x ^ @byteutil.rotl(x, 15) ^ @byteutil.rotl(x, 23))
}

///|
/// `compress` over a single zero block runs without panicking.
test "wb_compress_zero_block" {
  let state = FixedArray::makei(8, fn(i) { iv[i] })
  let block = Bytes::makei(64, fn(_i) { b'\x00' })
  compress(state, block, offset=0)
  // state must remain an 8-word array after compression
  assert_eq(state.length(), 8)
}
