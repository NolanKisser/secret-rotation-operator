package generator

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
)

func TestPassword(t *testing.T) {
	g := New()
	tests := []struct {
		name     string
		spec     rotationv1alpha1.GeneratorSpec
		wantLen  int
		alphabet string
	}{
		{"default length", rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorPassword}, 32, alphanumeric},
		{"custom length", rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorPassword, Length: 64}, 64, alphanumeric},
		{"with symbols", rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorPassword, Length: 200, Symbols: true}, 200, alphanumeric + symbols},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := g.Generate(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			if len(v) != tt.wantLen {
				t.Fatalf("len = %d, want %d", len(v), tt.wantLen)
			}
			for _, c := range string(v) {
				if !strings.ContainsRune(tt.alphabet, c) {
					t.Fatalf("character %q outside alphabet", c)
				}
			}
		})
	}
}

func TestPasswordsAreUnique(t *testing.T) {
	g := New()
	seen := map[string]bool{}
	for range 1000 {
		v, err := g.Generate(rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorPassword, Length: 16})
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(v)] {
			t.Fatalf("duplicate password %q", v)
		}
		seen[string(v)] = true
	}
}

func TestRandomBytes(t *testing.T) {
	g := New()

	b64, err := g.Generate(rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorRandomBytes, Length: 48})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil || len(raw) != 48 {
		t.Fatalf("base64 output decoded to %d bytes, err=%v", len(raw), err)
	}

	hx, err := g.Generate(rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorRandomBytes, Length: 16, Encoding: rotationv1alpha1.EncodingHex})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = hex.DecodeString(string(hx))
	if err != nil || len(raw) != 16 {
		t.Fatalf("hex output decoded to %d bytes, err=%v", len(raw), err)
	}
}

func TestRSAKey(t *testing.T) {
	v, err := New().Generate(rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorRSAKey, Bits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(v)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("expected PKCS#8 PEM block, got %v", block)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() != 2048 {
		t.Fatalf("expected 2048-bit RSA key, got %T", key)
	}
}

func TestErrors(t *testing.T) {
	g := New()
	if _, err := g.Generate(rotationv1alpha1.GeneratorSpec{Type: "Nope"}); err == nil {
		t.Error("expected error for unknown type")
	}
	if _, err := g.Generate(rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorRSAKey, Bits: 1024}); err == nil {
		t.Error("expected error for weak RSA key size")
	}
	broken := &Generator{Rand: failingReader{}}
	if _, err := broken.Generate(rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorPassword}); err == nil {
		t.Error("expected error when the random source fails")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy exhausted") }
