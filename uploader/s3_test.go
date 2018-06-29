package uploader

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCountingReaderRead(t *testing.T) {
	const expected = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	reader := strings.NewReader(expected)
	countingReader := &countingReader{reader: reader}

	bytes, err := ioutil.ReadAll(countingReader)
	assert.NoError(t, err)

	actual := string(bytes)

	assert.Equal(t, expected, actual)
	assert.Equal(t, len(expected), countingReader.bytesRead)
}
