/**
Copyright (C) 2020 Aaron Sky.

This file is part of asc-go, a package for working with Apple's
App Store Connect API.

asc-go is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

asc-go is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with asc-go.  If not, see <http://www.gnu.org/licenses/>.
*/

package asc

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrMissingPEM happens when the bytes cannot be decoded as a PEM block.
var ErrMissingPEM = errors.New("no PEM blob found")

// ErrInvalidPrivateKey happens when a key cannot be parsed as a ECDSA PKCS8 private key.
var ErrInvalidPrivateKey = errors.New("key could not be parsed as a valid ecdsa.PrivateKey")

// AuthTransport is an http.RoundTripper implementation that stores the JWT created.
// If the token expires, the Rotate function should be called to update the stored token.
type AuthTransport struct {
	Transport    http.RoundTripper
	jwtGenerator jwtGenerator
	inHouse      bool
}

type jwtGenerator interface {
	Token() (string, error)
	IsValid() bool
}

type standardJWTGenerator struct {
	keyID          string
	issuerID       string
	audience       string
	expireDuration time.Duration
	privateKey     *ecdsa.PrivateKey

	token string
}

// NewTokenConfig returns a new AuthTransport instance that customizes the Authentication header of the request during transport.
// It can be customized further by supplying a custom http.RoundTripper instance to the Transport field.
func NewTokenConfig(keyID string, issuerID string, expireDuration time.Duration, privateKey []byte, inHouse bool) (*AuthTransport, error) {
	key, err := jwt.ParseECPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, err
	}

	var audience string
	if inHouse == false {
		audience = "appstoreconnect-v1"
	} else {
		audience = "apple-developer-enterprise-v1"
	}

	gen := &standardJWTGenerator{
		keyID:          keyID,
		issuerID:       issuerID,
		audience:       audience,
		privateKey:     key,
		expireDuration: expireDuration,
	}
	_, err = gen.Token()

	return &AuthTransport{
		Transport:    newTransport(),
		jwtGenerator: gen,
	}, err
}

// RoundTrip implements the http.RoundTripper interface to set the Authorization header.
func (t AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.jwtGenerator.Token()
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	return t.transport().RoundTrip(req)
}

// Client returns a new http.Client instance for use with asc.Client.
func (t *AuthTransport) Client() (*http.Client, string) {
	if t.inHouse == false {
		return &http.Client{Transport: t}, "https://api.appstoreconnect.apple.com/"
	}
	return &http.Client{Transport: t}, "https://api.enterprise.developer.apple.com/"
}

func (t *AuthTransport) transport() http.RoundTripper {
	if t.Transport == nil {
		t.Transport = newTransport()
	}

	return t.Transport
}

func (g *standardJWTGenerator) Token() (string, error) {
	if g.IsValid() {
		return g.token, nil
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, g.claims())
	t.Header["kid"] = g.keyID

	token, err := t.SignedString(g.privateKey)
	if err != nil {
		return "", err
	}

	g.token = token

	return token, nil
}

func (g *standardJWTGenerator) IsValid() bool {
	if g.token == "" {
		return false
	}

	parsed, err := jwt.Parse(
		g.token,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("Unexpected signing Method: %v", token.Header["alg"])
			}
			return &g.privateKey.PublicKey, nil
		},
		jwt.WithAudience(g.audience),
		jwt.WithIssuer(g.issuerID),
	)
	if err != nil {
		fmt.Errorf("There was an error parsing token")
		return false
	}

	return parsed.Valid
}

func (g *standardJWTGenerator) claims() jwt.Claims {
	expiry := time.Now().Add(g.expireDuration)

	return jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{g.audience},
		Issuer:    g.issuerID,
		ExpiresAt: jwt.NewNumericDate(expiry),
	}
}

func newTransport() http.RoundTripper {
	return &http.Transport{
		IdleConnTimeout: defaultTimeout,
	}
}
