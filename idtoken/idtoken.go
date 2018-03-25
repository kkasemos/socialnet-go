package idtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	numParts  = 3
	delimeter = "."

	algoHS256 = "HS256"
	issLINE   = "https://access.line.me"
)

var (
	// ErrAlgHS256 header's alg field must be HS256.
	ErrAlgHS256 = errors.New("alg: must be HS256")
	// ErrIss payload's iss field must be https://access.line.me.
	ErrIss = errors.New("iss: must be " + issLINE)
	// ErrAud payload's aud field does not match client ID.
	ErrAud = errors.New("aud: not match client ID")
	// ErrExp payload's exp field, its value has passed current Unix time.
	ErrExp = errors.New("exp: has expired")
	// ErrSignature signature does not match.
	ErrSignature = errors.New("signature: not match")
)

// Content LINE user ID token.
type Content struct {
	Header    Header
	Payload   Payload
	Signature []byte
}

// Header LINE user ID token header.
type Header struct {
	Alg string `json:"alg"` // the algorithm used to encode the object. LINE Login only uses HMAC SHA-256.
}

// Payload LINE user ID token payload.
type Payload struct {
	Iss     string `json:"iss"`     // https://access.line.me. URL where the ID token is generated.
	Sub     string `json:"sub"`     // User ID for which the ID token is generated
	Aud     string `json:"aud"`     // Channel ID
	Exp     int64  `json:"exp"`     // The expiry date of the token. UNIX time.
	Iat     int64  `json:"iat"`     // Time that the ID token was generated. UNIX time.
	Nonce   string `json:"nonce"`   // The nonce value specified in the authorization URL. Not included if the nonce value was not specified in the authorization request.
	Name    string `json:"name"`    // User's display name. Not included if the profile scope was not specified in the authorization request.
	Picture string `json:"picture"` // User's profile image URL. Not included if the profile scope was not specified in the authorization request.
}

// Split token into 3 parts; header, payload and signature.
func Split(token string) []string {
	return strings.Split(token, delimeter)
}

// Decode decode id_token's header, payload and signature.
func Decode(raws []string) ([][]byte, error) {
	res := make([][]byte, numParts)
	for i, v := range raws {
		dec, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}

		res[i] = dec
	}
	return res, nil
}

// Unmarshal unmarshal header, payload and signature to Content.
func Unmarshal(parts [][]byte) (*Content, error) {
	c := &Content{}
	if err := json.Unmarshal(parts[0], &c.Header); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(parts[1], &c.Payload); err != nil {
		return nil, err
	}

	c.Signature = parts[2]
	return c, nil
}

// Verify verify Content whether it is valid.
func (c *Content) Verify(raws []string, clientID string, now time.Time) error {
	if c.Header.Alg != algoHS256 {
		return ErrAlgHS256
	}

	p := c.Payload
	if p.Iss != issLINE {
		return ErrIss
	}
	if p.Aud != clientID {
		return ErrAud
	}
	if p.Exp <= now.Unix() {
		return ErrExp
	}

	d := raws[0] + "." + raws[1]
	if CheckMAC([]byte(d), c.Signature, []byte(clientID)) {
		return ErrSignature
	}

	return nil
}

// CheckMAC reports whether msgMAC is a valid HMAC tag for msg.
// Copy from this page: https://golang.org/pkg/crypto/hmac/
func CheckMAC(msg, msgMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(msgMAC, expectedMAC)
}

// Parse parse token to Content also verify it, except the nonce.
func Parse(token string, clientID string) (*Content, error) {
	raws := Split(token)
	parts, err := Decode(raws)
	if err != nil {
		return nil, err
	}

	c, err := Unmarshal(parts)
	if err != nil {
		return nil, err
	}

	err = c.Verify(raws, clientID, time.Now())
	if err != nil {
		return nil, err
	}

	return c, nil
}
