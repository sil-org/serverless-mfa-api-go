package mfa

import (
	"log"
	"net/http"
)

type App struct {
	config EnvConfig
	db     *Storage
}

func (a *App) FakeError(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, "this is a test message generated to confirm Sentry is working", http.StatusInternalServerError)
	log.Printf("this is a test log entry generated to confirm Sentry is working")
}

// NewApp creates a new App containing configuration and service clients
func NewApp(cfg EnvConfig) *App {
	db, err := NewStorage(cfg.AWSConfig)
	if err != nil {
		log.Fatalf("failed to create storage client: %s", err)
	}

	return &App{
		config: cfg,
		db:     db,
	}
}

// GetConfig returns the config data for the App
func (a *App) GetConfig() EnvConfig {
	return a.config
}

// GetDB returns the database storage client for the App
func (a *App) GetDB() *Storage {
	return a.db
}
