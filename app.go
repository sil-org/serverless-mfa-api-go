package mfa

import (
	"log"
)

type App struct {
	config EnvConfig
	db     *Storage
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
