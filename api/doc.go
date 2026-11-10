// Package openapi embeds the on-disk OpenAPI document the daemon serves.
package openapi

import _ "embed"

// Document is the OpenAPI 3.0.3 contract. Path keys use the default /api/v1.
// The daemon rewrites those keys to http.api_prefix when it serves the document.
//
//go:embed openapi.yaml
var Document []byte
