package main

import (
	"log"
	"net/http"
	"os"

	"github.com/kelseyhightower/envconfig"

	mfa "github.com/silinternational/serverless-mfa-api-go"
	"github.com/silinternational/serverless-mfa-api-go/router"
)

var envConfig mfa.EnvConfig

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Server starting...")

	err := envconfig.Process("", &envConfig)
	if err != nil {
		log.Fatalf("error loading env vars: %s", err)
	}
	envConfig.InitAWS()
	mfa.SetConfig(envConfig)

	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	log.Println("Starting service on port 8080")
	app := mfa.NewApp(envConfig)
	mux := router.NewMux(app)
	log.Fatal(http.ListenAndServe(":8080", mux))
}
