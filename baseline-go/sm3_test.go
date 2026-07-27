package gmsm_oracle_test

import (
	"testing"

	"github.com/tjfoc/gmsm/sm3"
)

func genSm3() {
	msgs := []struct {
		name string
		msg  []byte
	}{
		{"abc", []byte("abc")},
		{"empty", []byte("")},
		{"hello", []byte("hello")},
		{"64B", []byte("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")},
	}
	// 200-byte deterministic message
	big := make([]byte, 200)
	for i := range big {
		big[i] = byte(i % 251)
	}
	msgs = append(msgs, struct {
		name string
		msg  []byte
	}{"200B", big})

	for _, m := range msgs {
		V.Sm3 = append(V.Sm3, Sm3Vector{
			Name:   m.name,
			Msg:    hexb(m.msg),
			Digest: hexb(sm3.Sm3Sum(m.msg)),
		})
	}
}

func TestSm3Known(t *testing.T) {
	if got := hexb(sm3.Sm3Sum([]byte("abc"))); got != "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" {
		t.Fatalf("sm3(abc) = %s, want 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", got)
	}
	if got := hexb(sm3.Sm3Sum([]byte(""))); got != "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b" {
		t.Fatalf("sm3(\"\") = %s", got)
	}
}
