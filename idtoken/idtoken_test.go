package idtoken

import (
	"testing"
	"time"

	"encoding/hex"
)

func Test_Decode(t *testing.T) {
	token := ""
	parts, _ := Decode(Split(token))

	if s := string(parts[0]); s != `{"alg":"HS256"}` {
		t.Errorf("Header: %s", s)
	}
	if s := string(parts[1]); s != `{"iss":"https://access.line.me","sub":"","aud":"","exp":1,"iat":1,"nonce":"","name":"Kasemosoth","picture":""}` {
		t.Errorf("Payload: %s", s)
	}
	if hex.EncodeToString(parts[2]) != "5775471a2982af19a78d1c9ec92dc57f07995ff4a31584543d523a2c089a584d" {
		t.Errorf("Signature: %s", hex.EncodeToString(parts[2]))
	}
}

func Test_Unmarshal(t *testing.T) {
	token := ""
	parts, _ := Decode(Split(token))
	c, err := Unmarshal(parts)

	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	if c.Header.Alg != "HS256" {
		t.Errorf("Alg: %s", c.Header.Alg)
	}

	p := c.Payload
	if p.Iss != "https://access.line.me" {
		t.Errorf("Iss: %s", p.Iss)
	}
	if p.Sub != "" {
		t.Errorf("Sub: %s", p.Sub)
	}
	if p.Aud != "" {
		t.Errorf("Aud: %s", p.Aud)
	}
	if p.Exp != 1 {
		t.Errorf("Exp: %d", p.Exp)
	}
	if p.Iat != 1 {
		t.Errorf("Iat: %d", p.Exp)
	}
}

func Test_Verify(t *testing.T) {
	token := ""
	raws := Split(token)
	parts, _ := Decode(raws)
	c, _ := Unmarshal(parts)
	err := c.Verify(raws, "1560824433", time.Now())

	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}
}
