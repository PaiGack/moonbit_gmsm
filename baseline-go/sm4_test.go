package gmsm_oracle_test

import (
	"encoding/hex"
	"testing"

	"github.com/tjfoc/gmsm/sm4"
)

func genSm4() {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")

	// single block known-answer test (GM/T 0002-2012 Appendix A)
	blk, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	V.Sm4Blk = append(V.Sm4Blk, Sm4BlockVector{
		Name: "kat", Key: hexb(key), Block: hexb(blk), Cipher: hexb(rawSm4Ecb(key, blk)),
	})

	// 32-byte ECB (two blocks, no padding)
	ecb32 := make([]byte, 32)
	for i := range ecb32 {
		ecb32[i] = byte((i*7 + 3) & 0xFF)
	}
	V.Sm4Ecb = append(V.Sm4Ecb, Sm4EcbVector{
		Name: "32B", Key: hexb(key), Plain: hexb(ecb32), Cipher: hexb(rawSm4Ecb(key, ecb32)),
	})

	// 48-byte ECB (three blocks)
	ecb48 := make([]byte, 48)
	for i := range ecb48 {
		ecb48[i] = byte((i*5 + 11) & 0xFF)
	}
	V.Sm4Ecb = append(V.Sm4Ecb, Sm4EcbVector{
		Name: "48B", Key: hexb(key), Plain: hexb(ecb48), Cipher: hexb(rawSm4Ecb(key, ecb48)),
	})

	// 32-byte CBC
	cbc32 := make([]byte, 32)
	for i := range cbc32 {
		cbc32[i] = byte((i*11 + 1) & 0xFF)
	}
	V.Sm4Cbc = append(V.Sm4Cbc, Sm4CbcVector{
		Name: "32B", Key: hexb(key), IV: hexb(iv), Plain: hexb(cbc32), Cipher: hexb(rawSm4Cbc(key, iv, cbc32)),
	})

	// 48-byte CBC
	cbc48 := make([]byte, 48)
	for i := range cbc48 {
		cbc48[i] = byte((i*3 + 7) & 0xFF)
	}
	V.Sm4Cbc = append(V.Sm4Cbc, Sm4CbcVector{
		Name: "48B", Key: hexb(key), IV: hexb(iv), 		Plain: hexb(cbc48), Cipher: hexb(rawSm4Cbc(key, iv, cbc48)),
	})
}

func TestSm4Known(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	blk, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	if got := hexb(rawSm4Ecb(key, blk)); got != "681edf34d206965e86b3e94f536e4246" {
		t.Fatalf("sm4 block KAT = %s, want 681edf34d206965e86b3e94f536e4246", got)
	}
	// Confirm gmsm's raw block matches the SDK's own cipher block API.
	c, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	c.Encrypt(out, blk)
	if hexb(out) != "681edf34d206965e86b3e94f536e4246" {
		t.Fatalf("sm4.NewCipher block = %s", hexb(out))
	}
}
