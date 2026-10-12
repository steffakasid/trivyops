package internal

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnzipFromReader(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		btZip, err := os.ReadFile("../test/result.zip")
		assert.NoError(t, err)
		btUnzip, err := unzipFromReader(bytes.NewReader(btZip), "trivy-result.json")
		assert.NoError(t, err)
		assert.NotNil(t, btUnzip)
	})

	t.Run("No such file", func(t *testing.T) {
		btZip, err := os.ReadFile("../test/result.zip")
		assert.NoError(t, err)
		btUnzip, err := unzipFromReader(bytes.NewReader(btZip), "not-there.json")
		assert.Error(t, err)
		assert.EqualError(t, err, "didn't find not-there.json in zip")
		assert.Nil(t, btUnzip)
	})
}
