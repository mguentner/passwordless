package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mguentner/passwordless/config"
	"github.com/mguentner/passwordless/crypto"
	"github.com/mguentner/passwordless/state"
	"github.com/rs/zerolog/log"
)

func GetStateAndConfig(w http.ResponseWriter, r *http.Request) (*state.State, *config.Config, bool) {
	state := r.Context().Value("state").(*state.State)
	configurable := r.Context().Value("config").(config.Configurable)
	if state == nil {
		log.Error().Msg("Setup error: No state in context")
		return nil, nil, false
	}
	if configurable == nil {
		log.Error().Msg("Setup error: No config in context")
		return nil, nil, false
	}
	config := configurable.GetConfig()
	return state, config, true
}

func HttpJSONError(w http.ResponseWriter, msg string, code int) {
	type JSONError struct {
		Msg string `json:"msg"`
	}
	jsonError := &JSONError{
		Msg: msg,
	}
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	err := encoder.Encode(jsonError)
	if err != nil {
		http.Error(w, "Fatal Encoder Error", http.StatusInternalServerError)
	}
}

type NoAuthorizationHeaderFound struct{}

func (e *NoAuthorizationHeaderFound) Error() string {
	return "NoAuthorizationHeaderFound"
}

type InvalidHeaderFormat struct{}

func (e *InvalidHeaderFormat) Error() string {
	return "InvalidHeaderFormat"
}

// Credits to the authors of https://github.com/auth0/go-jwt-middleware (MIT).
// Inspiration for some of the code comes from this project. However they
// currently (07/2021) depend of a fork of golang-jwt/jwt.
// Also, looking at the code itself, it makes more sense to implement it again
// to be consistent in the library as all the checking functions are already
// implemented in `../crypto/`

func ExtractAuthHeader(r *http.Request) (string, error) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return "", &NoAuthorizationHeaderFound{}
	}
	parts := strings.Fields(authorization)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", &InvalidHeaderFormat{}
	}
	return parts[1], nil
}

func WithJWTAuthorization(w http.ResponseWriter, r *http.Request) *http.Request {
	state, _, ok := GetStateAndConfig(w, r)
	if !ok {
		HttpJSONError(w, "Configuration Error", http.StatusInternalServerError)
		return nil
	}
	token, err := ExtractAuthHeader(r)
	if err != nil {
		HttpJSONError(w, err.Error(), http.StatusUnauthorized)
		return nil
	}
	claims, err := crypto.ValidateAccessToken(state.RSAKeyPairs, token)
	if err != nil {
		HttpJSONError(w, err.Error(), http.StatusUnauthorized)
		return nil
	}
	requestWithClaims := r.WithContext(context.WithValue(r.Context(), "accessToken", claims))
	return requestWithClaims
}

func WithJWTHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newRequest := WithJWTAuthorization(w, r)
		if newRequest == nil {
			return
		}
		h.ServeHTTP(w, newRequest)
	})
}
