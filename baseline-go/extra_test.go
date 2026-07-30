package gmsm_oracle_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
)

// ---------------------------------------------------------------------------
// SM3: multi-chunk (streaming) vectors
// ---------------------------------------------------------------------------

// genSm3Multi produces digests of messages fed to sm3.New() in several chunks.
// They are the reference for MoonBit's `sm3_sum_multi` and for the streaming
// `write` / `sum` / `reset` API.
func genSm3Multi() {
	cases := []struct {
		name   string
		chunks [][]byte
	}{
		{"abc_split", [][]byte{[]byte("a"), []byte("b"), []byte("c")}},
		{"empty_chunks", [][]byte{[]byte(""), []byte("hello"), []byte("")}},
		{"block_edge", [][]byte{
			[]byte("abcdabcdabcdabcdabcdabcdabcdabcd"),
			[]byte("abcdabcdabcdabcdabcdabcdabcdabcd"),
			[]byte("tail"),
		}},
		{"none", [][]byte{}},
	}
	for _, c := range cases {
		h := sm3.New()
		var all []byte
		hexChunks := []string{}
		for _, ch := range c.chunks {
			h.Write(ch)
			all = append(all, ch...)
			hexChunks = append(hexChunks, hexb(ch))
		}
		d := h.Sum(nil)
		// self-check: chunked hashing must equal the one-shot hash
		if !bytes.Equal(d, sm3.Sm3Sum(all)) {
			panic("sm3 chunked/one-shot mismatch")
		}
		V.Sm3Multi = append(V.Sm3Multi, Sm3MultiVector{
			Name: c.name, Chunks: hexChunks, Digest: hexb(d),
		})
	}
}

// TestSm3Streaming pins down the hash.Hash surface that MoonBit mirrors
// (Size / BlockSize / Reset).
func TestSm3Streaming(t *testing.T) {
	h := sm3.New()
	if h.Size() != 32 || h.BlockSize() != 64 {
		t.Fatalf("sm3 Size/BlockSize = %d/%d, want 32/64", h.Size(), h.BlockSize())
	}
	h.Write([]byte("garbage"))
	h.Reset()
	h.Write([]byte("abc"))
	if got := hexb(h.Sum(nil)); got != "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" {
		t.Fatalf("sm3 after Reset = %s", got)
	}
}

// ---------------------------------------------------------------------------
// SM4: padded mode wrappers (Sm4Ecb / Sm4Cbc / Sm4CFB / Sm4OFB)
// ---------------------------------------------------------------------------

// genSm4Modes produces vectors for the tjfoc "mode bool" wrappers, which embed
// PKCS7 padding and (for CBC/CFB/OFB) read the package-level IV set by SetIV.
func genSm4Modes() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	if err := sm4.SetIV(iv); err != nil {
		panic(err)
	}
	defer func() {
		// restore the library default so other generators are unaffected
		if err := sm4.SetIV(make([]byte, 16)); err != nil {
			panic(err)
		}
	}()

	plains := []struct {
		name  string
		plain []byte
	}{
		{"empty", []byte{}},
		{"5B", []byte("hello")},
		{"16B", mustHex("0123456789abcdeffedcba9876543210")},
		{"30B", seq(30, 3, 7)},
	}
	modes := []struct {
		name string
		fn   func(key, in []byte, mode bool) ([]byte, error)
	}{
		{"ecb", sm4.Sm4Ecb},
		{"cbc", sm4.Sm4Cbc},
		{"cfb", sm4.Sm4CFB},
		{"ofb", sm4.Sm4OFB},
	}
	for _, m := range modes {
		for _, p := range plains {
			ct, err := m.fn(key, p.plain, true)
			if err != nil {
				panic(err)
			}
			back, err := m.fn(key, ct, false)
			if err != nil {
				panic(err)
			}
			if !bytes.Equal(back, p.plain) {
				panic("sm4 " + m.name + " padded roundtrip mismatch")
			}
			V.Sm4Mode = append(V.Sm4Mode, Sm4ModeVector{
				Name: m.name + "_" + p.name, Mode: m.name,
				Key: hexb(key), IV: hexb(iv), Plain: hexb(p.plain), Cipher: hexb(ct),
			})
		}
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func seq(n, a, b int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*a + b) & 0xFF)
	}
	return out
}

// TestSm4CipherBlock pins the cipher.Block surface mirrored by MoonBit's
// SM4Cipher (BlockSize / Encrypt / Decrypt on a pre-expanded key).
func TestSm4CipherBlock(t *testing.T) {
	key := mustHex("0123456789ABCDEFFEDCBA9876543210")
	c, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockSize() != 16 {
		t.Fatalf("BlockSize = %d", c.BlockSize())
	}
	blk := mustHex("0123456789ABCDEFFEDCBA9876543210")
	ct := make([]byte, 16)
	c.Encrypt(ct, blk)
	pt := make([]byte, 16)
	c.Decrypt(pt, ct)
	if !bytes.Equal(pt, blk) {
		t.Fatal("cipher.Block roundtrip mismatch")
	}
}

// ---------------------------------------------------------------------------
// SM2: compression, raw C1C3C2 / C1C2C3 ciphertexts, marshal, key exchange
// ---------------------------------------------------------------------------

// full32 reports whether every value serializes to exactly 32 bytes. gmsm
// concatenates `big.Int.Bytes()` (no left padding) in several places, so we
// only emit vectors whose scalars have no leading zero byte; otherwise the
// fixed-width MoonBit encoding could not reproduce them.
func full32(vals ...*big.Int) bool {
	for _, v := range vals {
		if len(v.Bytes()) != 32 {
			return false
		}
	}
	return true
}

// genKey32 returns a key whose public coordinates are both exactly 32 bytes.
func genKey32() *sm2.PrivateKey {
	for i := 0; i < 100; i++ {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		if full32(priv.D, priv.PublicKey.X, priv.PublicKey.Y) {
			return priv
		}
	}
	panic("could not generate a 32-byte-aligned key")
}

func genSm2Extra() {
	// --- point compression (tjfoc uses a 0x00/0x01 prefix, not 0x02/0x03) ---
	for i := 0; i < 4; i++ {
		priv := genKey32()
		comp := sm2.Compress(&priv.PublicKey)
		back := sm2.Decompress(comp)
		if back.X.Cmp(priv.PublicKey.X) != 0 || back.Y.Cmp(priv.PublicKey.Y) != 0 {
			panic("sm2 compress/decompress self-check failed")
		}
		V.Sm2Cmp = append(V.Sm2Cmp, Sm2CompressVector{
			Name:       fmt.Sprintf("k%d", i),
			PrivD:      hexb(priv.D.Bytes()),
			PubX:       hexb(priv.PublicKey.X.Bytes()),
			PubY:       hexb(priv.PublicKey.Y.Bytes()),
			Compressed: hexb(comp),
		})
	}

	// --- raw C1C3C2 / C1C2C3 ciphertexts + ASN.1 conversion ---
	priv := genKey32()
	pub := &priv.PublicKey
	msgs := [][]byte{
		[]byte("raw mode message"),
		seq(16, 7, 3),
		seq(40, 5, 11),
	}
	for i, m := range msgs {
		c132, err := sm2.Encrypt(pub, m, rand.Reader, sm2.C1C3C2)
		if err != nil {
			panic(err)
		}
		c123, err := sm2.Encrypt(pub, m, rand.Reader, sm2.C1C2C3)
		if err != nil {
			panic(err)
		}
		asn1c, err := sm2.CipherMarshal(c132)
		if err != nil {
			panic(err)
		}
		// self-checks
		if d, err := sm2.Decrypt(priv, c132, sm2.C1C3C2); err != nil || !bytes.Equal(d, m) {
			panic("sm2 C1C3C2 self-check failed")
		}
		if d, err := sm2.Decrypt(priv, c123, sm2.C1C2C3); err != nil || !bytes.Equal(d, m) {
			panic("sm2 C1C2C3 self-check failed")
		}
		back, err := sm2.CipherUnmarshal(asn1c)
		if err != nil || !bytes.Equal(back, c132) {
			panic("sm2 CipherMarshal/CipherUnmarshal self-check failed")
		}
		V.Sm2Raw = append(V.Sm2Raw, Sm2RawVector{
			Name:   fmt.Sprintf("m%d", i),
			PrivD:  hexb(priv.D.Bytes()),
			PubX:   hexb(pub.X.Bytes()),
			PubY:   hexb(pub.Y.Bytes()),
			Msg:    hexb(m),
			C1C3C2: hexb(c132),
			C1C2C3: hexb(c123),
			Asn1:   hexb(asn1c),
		})
	}

	// --- key exchange ---
	for i, klen := range []int{16, 32} {
		privA, privB := genKey32(), genKey32()
		rprivA, rprivB := genKey32(), genKey32()
		ida := []byte("1234567812345678")
		idb := []byte("8765432187654321")
		kA, s1A, s2A, err := sm2.KeyExchangeA(klen, ida, idb, privA, &privB.PublicKey, rprivA, &rprivB.PublicKey)
		if err != nil {
			panic(err)
		}
		kB, s1B, s2B, err := sm2.KeyExchangeB(klen, ida, idb, privB, &privA.PublicKey, rprivB, &rprivA.PublicKey)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(kA, kB) || !bytes.Equal(s1A, s1B) || !bytes.Equal(s2A, s2B) {
			panic("sm2 key exchange self-check failed")
		}
		V.Sm2Kex = append(V.Sm2Kex, Sm2KexVector{
			Name:   fmt.Sprintf("k%d", i),
			Klen:   klen,
			IDA:    hexb(ida),
			IDB:    hexb(idb),
			PrivA:  hexb(privA.D.Bytes()),
			PubAX:  hexb(privA.PublicKey.X.Bytes()),
			PubAY:  hexb(privA.PublicKey.Y.Bytes()),
			PrivB:  hexb(privB.D.Bytes()),
			PubBX:  hexb(privB.PublicKey.X.Bytes()),
			PubBY:  hexb(privB.PublicKey.Y.Bytes()),
			RPrivA: hexb(rprivA.D.Bytes()),
			RPubAX: hexb(rprivA.PublicKey.X.Bytes()),
			RPubAY: hexb(rprivA.PublicKey.Y.Bytes()),
			RPrivB: hexb(rprivB.D.Bytes()),
			RPubBX: hexb(rprivB.PublicKey.X.Bytes()),
			RPubBY: hexb(rprivB.PublicKey.Y.Bytes()),
			K:      hexb(kA),
			S1:     hexb(s1A),
			S2:     hexb(s2A),
		})
	}
}

// TestSm2SignDataDigit pins the ASN.1 signature conversion helpers mirrored by
// MoonBit's sign_digit_to_sign_data / sign_data_to_sign_digit.
func TestSm2SignDataDigit(t *testing.T) {
	r := new(big.Int).SetBytes(mustHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
	s := new(big.Int).SetBytes(mustHex("7f00000000000000000000000000000000000000000000000000000000000001"))
	der, err := sm2.SignDigitToSignData(r, s)
	if err != nil {
		t.Fatal(err)
	}
	r2, s2, err := sm2.SignDataToSignDigit(der)
	if err != nil {
		t.Fatal(err)
	}
	if r.Cmp(r2) != 0 || s.Cmp(s2) != 0 {
		t.Fatal("SignDigitToSignData/SignDataToSignDigit roundtrip mismatch")
	}
}
