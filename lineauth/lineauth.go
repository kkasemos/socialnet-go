package lineauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

const (
	tokenURL = "https://api.line.me/oauth2/v2.1/token"
	authURL  = "https://access.line.me/oauth2/v2.1/authorize"

	defaultResponseType = "code"
	defaultScope        = "openid profile"
	defaultGrantType    = "authorization_code"
)

// Auth LINE authentication and authorization info.
type Auth struct {
	ResponseType string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	State        string
	Scope        string
	Nonce        string
	Prompt       string
	BotPrompt    string
}

// Authoriz LINE authorization code.
type Authoriz struct {
	Code                    string `json:"code"`
	State                   string `json:"state"`
	FriendshipStatusChanged bool   `json:"friendship_status_changed"`
}

// ParseAuthoriz parse authorization info from Rquest.
func ParseAuthoriz(r *http.Request) *Authoriz {
	a := &Authoriz{
		Code:  r.FormValue("code"),
		State: r.FormValue("state"),
		FriendshipStatusChanged: r.FormValue("friendship_status_changed") == "true",
	}
	return a
}

// Error error when a user denies the permissions.
type Error struct {
	Code        string
	Description string
	State       string
}

// Config LINE API configuration.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// Access LINE access info.
type Access struct {
	Token        string `json:"access_token"`
	ExpiredIn    string `json:"expired_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// UnmarshalAccess unmarshal json to Access
func UnmarshalAccess(data string) (*Access, error) {
	a := &Access{}
	if err := json.Unmarshal([]byte(data), a); err != nil {
		return nil, err
	}

	return a, nil
}

// NewAuth create a new LINE authentication.
func NewAuth(c Config) *Auth {
	a := &Auth{
		ResponseType: defaultResponseType,
		Scope:        defaultScope,
	}
	if c.ClientID != "" {
		a.ClientID = c.ClientID
	}
	if c.ClientSecret != "" {
		a.ClientSecret = c.ClientSecret
	}
	if c.RedirectURI != "" {
		a.RedirectURI = c.RedirectURI
	}
	return a
}

// CreateURL create an authorization URL with query parameters.
func (a Auth) CreateURL() string {
	return fmt.Sprintf("%s?response_type=%s&client_id=%s&redirect_uri=%s&state=%s&scope=%s&nonce=%s",
		authURL, url.QueryEscape(a.ResponseType),
		url.QueryEscape(a.ClientID), url.QueryEscape(a.RedirectURI),
		url.QueryEscape(a.State), url.QueryEscape(a.Scope), url.QueryEscape(a.Nonce))
}

// Request request an access token info.
func (a *Auth) Request(cli *http.Client, code string) (string, error) {
	vals := url.Values{
		"grant_type":    {defaultGrantType},
		"code":          {code},
		"redirect_uri":  {a.RedirectURI},
		"client_id":     {a.ClientID},
		"client_secret": {a.ClientSecret},
	}
	resp, err := cli.PostForm(tokenURL, vals)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
