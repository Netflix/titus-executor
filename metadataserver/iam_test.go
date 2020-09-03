package metadataserver

import (
	"testing"

	"github.com/google/uuid"
	"gotest.tools/assert"
)

func TestGenerateSessionName(t *testing.T) {
	taskID := uuid.New().String()
	assert.Equal(t, GenerateSessionName(taskID), "titus-"+taskID)
}

func TestFxGenerateSessionName(t *testing.T) {
	taskID := "foo bar"
	assert.Equal(t, GenerateSessionName(taskID), "titus-foo_bar")
}
