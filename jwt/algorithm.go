package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
)

// DefaulAlgorithms is used when NewConfig is given no algorithms.
var DefaulAlgorithms = []*Algorithm{
	HS256,
	HS512,
}

var (
	HS256 = NewAlgorithm("HS256", func(secret []byte) hash.Hash {
		return hmac.New(sha256.New, secret)
	})
	HS512 = NewAlgorithm("HS512", func(secret []byte) hash.Hash {
		return hmac.New(sha512.New, secret)
	})
)

type Algorithm struct {
	name     string
	header   string
	hashFunc func(secret []byte) hash.Hash
}

func NewAlgorithm(name string, hashFunc func(secret []byte) hash.Hash) *Algorithm {
	return &Algorithm{
		name:     name,
		header:   base64.URLEncoding.EncodeToString([]byte(`{"alg":"` + name + `","typ":"JWT"}`)),
		hashFunc: hashFunc,
	}
}

func (alg *Algorithm) String() string {
	return alg.name
}
