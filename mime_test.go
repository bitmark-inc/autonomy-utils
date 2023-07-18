package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetMIMETypeWithFilenameOnly(t *testing.T) {
	mimeType := GetMIMEType("abc.json", nil)
	assert.Equal(t, "application/json", mimeType)
	mimeType = GetMIMEType("test", nil)
	assert.Equal(t, "", mimeType)
}
