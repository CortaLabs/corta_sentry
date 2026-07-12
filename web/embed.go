package web

import "embed"

// Dist is produced by Vite and embedded in production releases.
//
//go:embed dist/*
var Dist embed.FS
