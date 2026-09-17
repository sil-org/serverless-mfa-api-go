#!/bin/bash
# Convenience script to run cmd/u2f with local.env variables loaded

export $(grep -v '^#' ./local.env | grep -v '^$' | xargs)

go run ./cmd/u2f "$@"
