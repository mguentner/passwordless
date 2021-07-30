package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mguentner/passwordless/config"
	"github.com/mguentner/passwordless/crypto"
	"github.com/mguentner/passwordless/handlers"
	"github.com/mguentner/passwordless/middleware"
	"github.com/mguentner/passwordless/state"
	"github.com/rs/cors"
	"github.com/rs/zerolog/log"
	flag "github.com/spf13/pflag"
)

var (
	configPath string
)

// This is a sample application uses all parts of the library
func main() {
	flag.StringVar(&configPath, "configPath", "config.yaml", "path to the config file")
	flag.Parse()
	config, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		log.Fatal().Msgf("Could not read config: %v", err)
	}
	rsaKeys, err := crypto.ReadRSAKeysFromPath(config.KeyPath)
	if err != nil {
		log.Fatal().Msgf("Could setup crypto %v", err)
	}
	state, err := state.NewState(*config, rsaKeys)
	if err != nil {
		log.Fatal().Msgf("Could create state: %v", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/login", handlers.RequestTokenHandler).Methods("POST")
	router.HandleFunc("/api/auth", handlers.AuthenticateHandler).Methods("POST")
	router.HandleFunc("/api/refresh", handlers.RefreshHandler).Methods("POST")
	router.HandleFunc("/api/keys", handlers.PublicKeyHandler).Methods("GET")

	protectedRouter := router.PathPrefix("/api").Subrouter()
	protectedRouter.Use(middleware.WithJWTHandler)
	protectedRouter.HandleFunc("/info", handlers.ClaimsInfoHandler).Methods("GET")

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	router.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := cors.AllowAll().Handler(router)
	ctxHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "state", state)
		ctx = context.WithValue(ctx, "config", config)
		corsHandler.ServeHTTP(w, r.WithContext(ctx))
	})
	log.Info().Msgf("Starting to listen on port %d", config.ListenPort)
	http.ListenAndServe(fmt.Sprintf(":%d", config.ListenPort), ctxHandler)
	return
}
