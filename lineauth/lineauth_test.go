package lineauth

import (
	"testing"
)

func Test_NewAuth(t *testing.T) {
	c := Config{
		ClientID:    "client_id",
		RedirectURI: "redirect_uri",
	}
	a := NewAuth(c)

	if a.ClientID == "" || a.ClientID != c.ClientID {
		t.Errorf("ClientID: %s %s", a.ClientID, c.ClientID)
	}
	if a.ClientSecret == "" || a.ClientSecret != c.ClientSecret {
		t.Errorf("ClientSecret: %s %s", a.ClientSecret, c.ClientSecret)
	}
	if a.RedirectURI == "" || a.RedirectURI != c.RedirectURI {
		t.Errorf("RedirectURI: %s %s", a.RedirectURI, c.RedirectURI)
	}
}

func Test_CreateURL(t *testing.T) {
	c := Config{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURI:  "redirect_uri",
	}
	a := NewAuth(c)
	a.State = "state"

	url := "https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id=client_id&redirect_uri=redirect_uri&state=state&scope=openid+profile&nonce="
	if u := a.CreateURL(); u != url {
		t.Errorf("URL: %s", u)
	}
}

func Test_UnmarshalAccess(t *testing.T) {
	s := `
		{
			"access_token":"",
			"token_type":"Bearer",
			"refresh_token":"",
			"expires_in":2592000,
			"scope":"openid profile",
			"id_token":""
		}
		`
	var a *Access
	var err error
	if a, err = UnmarshalAccess(s); err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	if a.Token != "" {
		t.Errorf("access_token: %s", a.Token)
	}
	if a.TokenType != "Bearer" {
		t.Errorf("token_type: %s", a.TokenType)
	}
}
