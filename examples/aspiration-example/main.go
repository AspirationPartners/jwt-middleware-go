package main

import (
	"github.com/spf13/viper"
	"net/http"
	"fmt"
	"github.com/AspirationPartners/jwt-middleware-go"
)

var secureHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user := jwtmiddleware.GetAspirationUserFromRequest(r)
	if !user.HasClaim("resource.action") { // Checks if user has the claim
		http.Error(w, "Not authorized", 401)
		return
	}

	fmt.Fprintln(w, user.ToString())
	fmt.Fprintln(w, "Simple Claims Checks:")
	fmt.Fprintf(w, "resource.action=%t\n", user.HasClaim("resource.action"))
	fmt.Fprintf(w, "resourceX.actionX=%t\n", user.HasClaim("resourceX.actionX"))
})

func main() {
	viper.AutomaticEnv()
	viper.SetDefault("JWT_SECRET", "secret")
	viper.SetDefault("JWT_SIGNING_METHOD", "hs256")

	jwt := jwtmiddleware.SetupAspirationJWTMiddleware(viper.GetString("JWT_SECRET"), viper.GetString("JWT_SIGNING_METHOD"))

	http.ListenAndServe("0.0.0.0:9933", jwt(secureHandler))
}
