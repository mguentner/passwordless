package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	"github.com/mguentner/passwordless/config"
	"github.com/mguentner/passwordless/crypto"
	"github.com/mguentner/passwordless/middleware"
	"github.com/mguentner/passwordless/operations"
	"github.com/mguentner/passwordless/state"
	"github.com/rs/zerolog/log"
)

type RequestTokenPayload struct {
	Email *string `json:"email,omitempty"`
}

func (p RequestTokenPayload) validate() bool {
	if p.Email != nil {
		_, err := mail.ParseAddress(*p.Email)
		if err == nil {
			return true
		}
	}
	return false
}

func RequestTokenHandler(w http.ResponseWriter, r *http.Request) {
	state, config, ok := middleware.GetStateAndConfig(w, r)
	if !ok {
		return
	}

	var payload RequestTokenPayload
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(&payload)
	if err != nil {
		middleware.HttpJSONError(w, fmt.Sprintf("Bad payload: %v", err), http.StatusUnauthorized)
		return
	}
	if !payload.validate() {
		middleware.HttpJSONError(w, fmt.Sprintf("Invalid payload: %v", err), http.StatusUnauthorized)
		return
	}
	remoteAddr := strings.Split(r.RemoteAddr, ":")[0]
	err = operations.GenerateAndStoreAndDeliverTokenForIdentifier(*config, *state, *payload.Email, remoteAddr)
	if err != nil {
		middleware.HttpJSONError(w, fmt.Sprintf("Could not execute operation: %v", err), http.StatusUnauthorized)
		return
	}
	w.WriteHeader(200)
	return
}

type AuthenicatePayload struct {
	Identifier string `json:"identifier"`
	Token      string `json:"token"`
}

type AccessRefreshKeysResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func issueAccessAndRefreshTokenForIdentifier(w http.ResponseWriter, config config.Config, state state.State, identifier string) {
	accessToken, err := crypto.CreateAccessToken(config, state.RSAKeyPairs, identifier)
	if err != nil {
		middleware.HttpJSONError(w, fmt.Sprintf("Could not execute operation: %v", err), http.StatusInternalServerError)
		return
	}
	refreshToken, err := crypto.CreateRefreshToken(config, state.RSAKeyPairs, identifier)
	if err != nil {
		middleware.HttpJSONError(w, fmt.Sprintf("Could not execute operation: %v", err), http.StatusInternalServerError)
		return
	}
	response := AccessRefreshKeysResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		middleware.HttpJSONError(w, fmt.Sprintf("Could not marshal: %v", err), http.StatusInternalServerError)
		return
	}
}

func AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	state, config, ok := middleware.GetStateAndConfig(w, r)
	if !ok {
		return
	}
	var payload AuthenicatePayload
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(&payload)
	if err != nil {
		log.Warn().Msgf("Bad payload: %s", err.Error())
		middleware.HttpJSONError(w, fmt.Sprintf("Bad payload: %v", err), http.StatusUnauthorized)
		return
	}
	err = operations.InvalidateToken(*state, payload.Identifier, payload.Token)
	if err != nil {
		middleware.HttpJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	issueAccessAndRefreshTokenForIdentifier(w, *config, *state, payload.Identifier)
	return
}

type RefreshPayload struct {
	RefreshToken string `json:"refreshToken"`
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	state, config, ok := middleware.GetStateAndConfig(w, r)
	if !ok {
		return
	}
	var payload RefreshPayload
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(&payload)
	if err != nil {
		log.Warn().Msgf("Bad payload: %s", err.Error())
		middleware.HttpJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	claims, err := crypto.ValidateRefreshToken(state.RSAKeyPairs, payload.RefreshToken)
	if err != nil {
		log.Warn().Msgf("Bad token: %s", err.Error())
		middleware.HttpJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	issueAccessAndRefreshTokenForIdentifier(w, *config, *state, claims.Identifier)
	return
}

func ClaimsInfoHandler(w http.ResponseWriter, r *http.Request) {
	accessToken, ok := r.Context().Value("accessToken").(*crypto.DefaultClaims)
	if !ok || accessToken == nil {
		middleware.HttpJSONError(w, "No accessToken found", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	err := encoder.Encode(accessToken)
	if err != nil {
		log.Error().Msgf("Could not marshal: %v", err)
		middleware.HttpJSONError(w, "Encoder error", http.StatusInternalServerError)
		return
	}
	return
}

type PublicKeyResponseItem struct {
	PublicKeyPEM         string `yaml:"key"`
	ValidFromUnixSeconds int64  `yaml:"validFrom"`
}

func PublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	state, _, ok := middleware.GetStateAndConfig(w, r)
	if !ok {
		return
	}
	response := []PublicKeyResponseItem{}
	for _, keyPair := range state.RSAKeyPairs {
		response = append(response, PublicKeyResponseItem{
			ValidFromUnixSeconds: keyPair.ValidFrom,
			PublicKeyPEM:         keyPair.PublicKeyPEM,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	err := encoder.Encode(response)
	if err != nil {
		log.Error().Msgf("Could not marshal: %v", err)
		middleware.HttpJSONError(w, "Encoder error", http.StatusInternalServerError)
		return
	}
	return
}
