package gmsm_oracle_test

import (
	"encoding/hex"
	"testing"

	"github.com/tjfoc/gmsm/sm4"
)

func rawCFB(key, iv, pt []byte) []byte {
	c, _ := sm4.NewCipher(key)
	out := make([]byte, len(pt))
	reg := make([]byte, 16)
	copy(reg, iv)
	for i := 0; i < len(pt); i += 16 {
		ks := make([]byte, 16)
		c.Encrypt(ks, reg)
		for j := 0; j < 16; j++ {
			out[i+j] = ks[j] ^ pt[i+j]
		}
		copy(reg, out[i:i+16])
	}
	return out
}

func rawOFB(key, iv, data []byte) []byte {
	c, _ := sm4.NewCipher(key)
	out := make([]byte, len(data))
	reg := make([]byte, 16)
	copy(reg, iv)
	for i := 0; i < len(data); i += 16 {
		ks := make([]byte, 16)
		c.Encrypt(ks, reg)
		for j := 0; j < 16; j++ {
			out[i+j] = ks[j] ^ data[i+j]
		}
		copy(reg, ks)
	}
	return out
}

func TestDumpVectors(t *testing.T) {
	key, _ := hex.DecodeString("31323334353637383930616263646566") // "1234567890abcdef"
	iv, _ := hex.DecodeString("30303030303030303030303030303030") // "0000000000000000"
	data16, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	data32 := make([]byte, 32)
	for i := range data32 {
		data32[i] = byte((i*7 + 3) & 0xFF)
	}
	data48 := make([]byte, 48)
	for i := range data48 {
		data48[i] = byte((i*5 + 11) & 0xFF)
	}

	for _, pt := range [][]byte{data16, data32, data48} {
		t.Logf("CFB key=%s iv=%s pt=%s ct=%s", hex.EncodeToString(key), hex.EncodeToString(iv), hex.EncodeToString(pt), hex.EncodeToString(rawCFB(key, iv, pt)))
		t.Logf("OFB key=%s iv=%s pt=%s ct=%s", hex.EncodeToString(key), hex.EncodeToString(iv), hex.EncodeToString(pt), hex.EncodeToString(rawOFB(key, iv, pt)))
	}

	// GCM via gmsm (standard, no padding)
	gkey, _ := hex.DecodeString("31323334353637383930616263646566")
	giv := make([]byte, 16)
	gdata16, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	gdata20 := make([]byte, 20)
	for i := range gdata20 {
		gdata20[i] = byte((i*3 + 7) & 0xFF)
	}
	gdata32 := make([]byte, 32)
	for i := range gdata32 {
		gdata32[i] = byte((i*11 + 1) & 0xFF)
	}
	aads := [][]byte{
		{},
		{0x01, 0x23, 0x45, 0x67, 0x89},
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
	}
	for _, pt := range [][]byte{gdata16, gdata20, gdata32} {
		for ai, a := range aads {
			ct, tag, err := sm4.Sm4GCM(gkey, giv, pt, a, true)
			if err != nil {
				t.Fatalf("gcm enc err: %v", err)
			}
			t.Logf("GCM key=%s iv=%s aad=%d pt=%s ct=%s tag=%s", hex.EncodeToString(gkey), hex.EncodeToString(giv), ai, hex.EncodeToString(pt), hex.EncodeToString(ct), hex.EncodeToString(tag))
		}
	}
}
