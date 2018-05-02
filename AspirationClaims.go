package jwtmiddleware

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"github.com/auth0/go-jwt-middleware"
)

type AspirationClaims struct {
	UserName string   `json:"user_name,omitempty"`
	UserId   int64    `json:"userId,omitempty"`
	ClientId string   `json:"client_id,omitempty"`
	Claims   []string `json:"claims,omitempty"`
	*jwt.StandardClaims
}

func (d AspirationClaims) ToString() string {
	return fmt.Sprintf("%s/%d (%s)", d.Issuer, d.UserId, d.UserName)
}

func (d AspirationClaims) HasClaim(claim string) bool {
	for _, a := range d.Claims {
		if a == claim {
			return true
		}
	}
	return false
}

func GetAspirationUserFromRequest(r *http.Request) *AspirationClaims {
	return r.Context().Value("user").(*jwt.Token).Claims.(*AspirationClaims)
}

func SetupAspirationJWTMiddleware(secret string, signingMethod string) func(http.Handler) (http.Handler) {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
		SigningMethod: jwt.GetSigningMethod(signingMethod),
		ClaimsFactory: func() jwt.Claims { return &AspirationClaims{} },
	})

	return jwtMiddleware.Handler
}
