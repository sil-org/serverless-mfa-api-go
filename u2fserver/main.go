package main

import (
	"log"
	"net/http"
	"os"

	u2fsim "github.com/silinternational/serverless-mfa-api-go/u2fsimulator"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Println("U2f Simulator Server starting...")

	// ListenAndServe starts an HTTP server with a given address and
	// handler defined in NewRouter.
	log.Println("Starting service on port 8080")
	router := newRouter()
	log.Fatal(http.ListenAndServe(":8080", router))
}

// newRouter forms a new http.ServeMux
func newRouter() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /u2f/registration", u2fsim.U2fRegistration)
	return mux
}
