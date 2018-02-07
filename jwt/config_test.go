package jwt_test

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	"hash"
	"testing"

	"github.com/jban332/kin-auth/jwt"
)

type Example struct {
	Algorithm     *jwt.Algorithm `json:",omitempty"`
	Secret        string         `json:",omitempty"`
	Payload       string         `json:",omitempty"`
	Token         string
	DecodingError error `json:",omitempty"`
}

func (example *Example) String() string {
	data, err := json.MarshalIndent(example, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(data)
}

// Generated with:
// https://jwt.io/
var ValidExamples = []*Example{
	{
		Secret:  "secret",
		Payload: `{}`,
		Token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
	},
}

var HS160 = jwt.NewAlgorithm("HS160", func(secret []byte) hash.Hash {
	return hmac.New(sha512.New, secret)
})

var DecodingErrorExamples = []*Example{
	{
		// Invalid token
		Token:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9--°ERROR°--.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
		DecodingError: jwt.ErrHeaderParsing,
	},
	{
		// Invalid token
		Token:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M--°ERROR°--",
		DecodingError: jwt.ErrSignatureParsing,
	},
	{
		// jwt.ErrHeaderAlgorithm
		Algorithm:     jwt.HS256,
		Secret:        "secret",
		Payload:       "abc",
		Token:         jwt.NewConfig("secret", HS160).EncodeToString(nil, []byte("abc")),
		DecodingError: jwt.ErrHeaderAlgorithm,
	},
	{
		// jwt.ErrSignatureValue
		Secret:        "secret",
		Payload:       "abc",
		Token:         jwt.NewConfig("otherSecret").EncodeToString(nil, []byte("abc")),
		DecodingError: jwt.ErrSignatureValue,
	},
}

func TestExamples(t *testing.T) {
	for _, example := range ValidExamples {
		testValidExample(t, example)
	}
	for _, example := range DecodingErrorExamples {
		testDecodingExample(t, example)
	}
}

func testValidExample(t *testing.T, example *Example) {
	algorithms := []*jwt.Algorithm{}
	if a := example.Algorithm; a != nil {
		algorithms = append(algorithms, a)
	}
	config := jwt.NewConfig(example.Secret, algorithms...)
	token := config.EncodeToString(nil, []byte(example.Payload))
	if token != example.Token {
		t.Errorf("\nENCODED TOKEN IS INCORRECT\n\nExample:\n%v\nExpected token:\n%v\nActual token:\n%v\n", example, example.Token, token)
		return
	}
	testDecodingExample(t, example)
}

func testDecodingExample(t *testing.T, example *Example) {
	config := jwt.NewConfig(example.Secret)
	payloadBytes, err := config.DecodeString(nil, example.Token)
	if example.DecodingError != nil {
		if err != example.DecodingError {
			t.Errorf("\nDECODING ERROR IS INCORRECT\n\nExample:\n%v\nActual error:\n%v\n", example, err)
		}
		return
	}
	payload := string(payloadBytes)
	if payload != example.Payload {
		t.Errorf("\nDECODED PAYLOAD IS INCORRECT\n\nExample:\n%v\nActual payload:\n%v\n", example, payload)
		return
	}
}
