package rand

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type RandSuite struct {
	suite.Suite
}

func TestRandSuite(t *testing.T) {
	suite.Run(t, new(RandSuite))
}

func (s *RandSuite) TestHex_WithFakeReader() {
	assert := s.Assert()

	fake := bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04})
	h, err := Hex(4, fake)
	assert.NoError(err)
	assert.Equal("01020304", h)
}

func (s *RandSuite) TestBytes_Length() {
	assert := s.Assert()

	b, err := Bytes(32, nil)
	assert.NoError(err)
	assert.Len(b, 32)
}

func (s *RandSuite) TestBytes_Guards() {
	assert := s.Assert()

	_, err := Bytes(0, nil)
	assert.Error(err)
	assert.ErrorContains(err, "n must be > 0")

	_, err = Bytes(MaxTokenBytes+1, nil)
	assert.Error(err)
	assert.ErrorContains(err, fmt.Sprintf("n too large: %d", MaxTokenBytes+1))
}
