package main

import (
	"log/slog"
	"net/http"
	"os"

	mfa "github.com/sil-org/serverless-mfa-api-go"
	u2fsim "github.com/sil-org/serverless-mfa-api-go/u2fsimulator"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	slog.Info("U2f Simulator Server starting...")

	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	slog.Info("Starting service on port 8080")
	router := newRouter()
	if err := http.ListenAndServe(":8080", router); err != nil {
		mfa.Fatal("server stopped", err)
	}
}

// newRouter forms a new http.ServeMux
func newRouter() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /u2f/registration", u2fsim.U2fRegistration)
	return mux
}
