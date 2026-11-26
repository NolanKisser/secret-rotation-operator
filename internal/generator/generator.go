// Package generator produces cryptographically secure secret material.
package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
)

const (
	alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// Symbols chosen to be safe inside URLs, shells, and connection strings
	// without quoting: no quotes, backslash, '$', '@', ':', '/', or '%'.
	symbols = "-_.~!^*+=,"

	defaultLength = 32
)

// Generator produces new values. The random source is injectable so tests can
// be deterministic; production code uses crypto/rand.Reader.
type Generator struct {
	Rand io.Reader
}

// New returns a Generator backed by crypto/rand.
func New() *Generator { return &Generator{Rand: rand.Reader} }

// Generate produces a value according to spec.
func (g *Generator) Generate(spec rotationv1alpha1.GeneratorSpec) ([]byte, error) {
	length := int(spec.Length)
	if length <= 0 {
		length = defaultLength
	}
	switch spec.Type {
	case rotationv1alpha1.GeneratorPassword:
		alphabet := alphanumeric
		if spec.Symbols {
			alphabet += symbols
		}
		return g.password(length, alphabet)
	case rotationv1alpha1.GeneratorRandomBytes:
		return g.randomBytes(length, spec.Encoding)
	case rotationv1alpha1.GeneratorRSAKey:
		return g.rsaKey(int(spec.Bits))
	default:
		return nil, fmt.Errorf("unknown generator type %q", spec.Type)
	}
}

// password draws each character uniformly from alphabet. rand.Int avoids the
// modulo bias of the naive `b % len(alphabet)` approach.
func (g *Generator) password(length int, alphabet string) ([]byte, error) {
	out := make([]byte, length)
	upper := big.NewInt(int64(len(alphabet)))
	for i := range out {
		n, err := rand.Int(g.Rand, upper)
		if err != nil {
			return nil, fmt.Errorf("reading random source: %w", err)
		}
		out[i] = alphabet[n.Int64()]
	}
	return out, nil
}

func (g *Generator) randomBytes(n int, enc rotationv1alpha1.Encoding) ([]byte, error) {
	raw := make([]byte, n)
	if _, err := io.ReadFull(g.Rand, raw); err != nil {
		return nil, fmt.Errorf("reading random source: %w", err)
	}
	switch enc {
	case rotationv1alpha1.EncodingHex:
		return []byte(hex.EncodeToString(raw)), nil
	case rotationv1alpha1.EncodingBase64, "":
		return []byte(base64.StdEncoding.EncodeToString(raw)), nil
	default:
		return nil, fmt.Errorf("unknown encoding %q", enc)
	}
}

func (g *Generator) rsaKey(bits int) ([]byte, error) {
	switch bits {
	case 2048, 3072, 4096:
	case 0:
		bits = 2048
	default:
		return nil, fmt.Errorf("unsupported RSA key size %d", bits)
	}
	key, err := rsa.GenerateKey(g.Rand, bits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling RSA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
