package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/kelseyhightower/envconfig"

	mfa "github.com/sil-org/serverless-mfa-api-go"
	"github.com/sil-org/serverless-mfa-api-go/router"
)

var envConfig mfa.EnvConfig

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	slog.Info("Server starting...")

	err := envconfig.Process("", &envConfig)
	if err != nil {
		slog.Error("error loading env vars", "error", err)
		os.Exit(1)
	}
	envConfig.InitAWS()
	mfa.SetConfig(envConfig)

	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	slog.Info("Starting service on port 8080")
	app := mfa.NewApp(envConfig)
	mux := router.NewMux(app)
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
