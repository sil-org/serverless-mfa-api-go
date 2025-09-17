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

// route is used to pass information about a particular route.
type route struct {
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// Define our routes.
var routes = []route{
	//   For information on this, see the doc comment for u2fsimulator.U2fRegistration
	{
		"POST /u2f/registration",
		u2fsim.U2fRegistration,
	},
}

// newRouter forms a new http.ServeMux
func newRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// Assign the handlers to run when endpoints are called.
	for _, r := range routes {
		mux.HandleFunc(r.Pattern, r.HandlerFunc)
	}

	return mux
}
