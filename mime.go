package utils

import (
	"path/filepath"

	"github.com/gabriel-vasile/mimetype"
)

// GetMIMEType returns mimetype based on the file name and optional header bytes
func GetMIMEType(filename string, fileHeader []byte) string {
	switch filepath.Ext(filename) {
	case ".css":
		return "text/css"
	case ".js", ".mjs":
		return "text/javascript"
	case ".html", ".htm", ".shtml":
		return "text/html"
	case ".csv":
		return "text/csv"
	case ".xml":
		return "application/xml"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".json":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	default:
		if fileHeader != nil {
			return mimetype.Detect(fileHeader).String()
		}
	}
	return ""
}
