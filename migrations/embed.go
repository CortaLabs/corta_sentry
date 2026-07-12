package migrations

import "embed"

// FS contains the immutable, repository-local database migrations.
//
//go:embed *.sql
var FS embed.FS
