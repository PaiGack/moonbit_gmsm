package gmsm_oracle_test

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func genSm2() {
	r := newDetReader()
	priv, err := sm2.GenerateKey(r)
	if err != nil {
		panic(err)
	}
	pub := &priv.PublicKey

	xBytes := make([]byte, 32)
	pub.X.FillBytes(xBytes)
	yBytes := make([]byte, 32)
	pub.Y.FillBytes(yBytes)
	dBytes := make([]byte, 32)
	priv.D.FillBytes(dBytes)
	pubX, pubY, privD := hexb(xBytes), hexb(yBytes), hexb(dBytes)

	// --- encryption vectors (MoonBit decrypts these) ---
	// NOTE: gmsm's Encrypt infinite-loops on an empty plaintext (its KDF
	// returns !ok for length 0), so we only use non-empty messages here.
	// MoonBit's own sm2 wbtest already covers the empty-plaintext case.
	encMsgs := [][]byte{
		[]byte("a"),
		[]byte("hello sm2"),
		make([]byte, 16),
		make([]byte, 30),
		make([]byte, 64),
	}
	for i, m := range encMsgs {
		cipher, err := pub.EncryptAsn1(m, r)
		if err != nil {
			panic(err)
		}
		// self-check: Go must be able to decrypt what it produced
		dec, err := priv.DecryptAsn1(cipher)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(dec, m) {
			panic("sm2 encrypt/decrypt self-check failed")
		}
		V.Sm2Enc = append(V.Sm2Enc, Sm2EncVector{
			Name:   fmt.Sprintf("m%d", i),
			PubX:   pubX,
			PubY:   pubY,
			PrivD:  privD,
			Msg:    hexb(m),
			Cipher: hexb(cipher),
		})
	}

	// --- signature vectors (MoonBit verifies these) ---
	cases := []struct {
		uid string
		msg string
	}{
		{"1234567812345678", "hello sm2 sign"},
		{"1234567812345678", "another message for signing!!! 1234567890"},
		{"sm2-cross-uid", "uid differs from default"},
	}
	for i, c := range cases {
		uid := []byte(c.uid)
		msg := []byte(c.msg)
		rr, ss, err := sm2.Sm2Sign(priv, msg, uid, r)
		if err != nil {
			panic(err)
		}
		if !sm2.Sm2Verify(pub, msg, uid, rr, ss) {
			panic("sm2 sign/verify self-check failed")
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{rr, ss})
		if err != nil {
			panic(err)
		}
		V.Sm2Sig = append(V.Sm2Sig, Sm2SigVector{
			Name: fmt.Sprintf("m%d", i),
			PubX: pubX,
			PubY: pubY,
			UID:  hexb(uid),
			Msg:  hexb(msg),
			R:    hexb(rr.Bytes()),
			S:    hexb(ss.Bytes()),
			Der:  hexb(der),
		})
	}
}

func TestSm2Roundtrip(t *testing.T) {
	// Independent key + crypto/rand for a true randomized round-trip check.
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("roundtrip check with crypto/rand")
	c, err := priv.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d, err := priv.DecryptAsn1(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d, msg) {
		t.Fatal("encrypt/decrypt roundtrip mismatch")
	}
	sig, err := priv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey.Verify(msg, sig) {
		t.Fatal("signature verify failed")
	}
}
