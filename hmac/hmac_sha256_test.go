package hmac

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/suite"
)

type HmacSha256SumSuite struct {
	suite.Suite
	key     []byte
	payload []byte
	tag     []byte
}

func TestHmacSha256SumSuite(t *testing.T) {
	suite.Run(t, new(HmacSha256SumSuite))
}

func (s *HmacSha256SumSuite) TestComputeHMACSHA256_OK() {
	assert := s.Assert()

	b, err := ComputeHMACSHA256(s.key, s.payload)
	assert.NoError(err)
	assert.Equal(s.tag, b)
}

func (s *HmacSha256SumSuite) TestComputeHMACSHA256_OK_empty_payload() {
	assert := s.Assert()

	b, err := ComputeHMACSHA256(s.key, []byte(""))
	assert.NoError(err)
	assert.NotNil(b)
}

func (s *HmacSha256SumSuite) TestComputeHMACSHA256_Error_empty_key() {
	assert := s.Assert()

	b, err := ComputeHMACSHA256([]byte(""), s.payload)
	assert.ErrorContains(err, "empty key")
	assert.Nil(b)
}

func (s *HmacSha256SumSuite) TestVerifyHMACSHA256_OK() {
	assert := s.Assert()

	ok, err := VerifyHMACSHA256(s.key, s.payload, s.tag)
	assert.NoError(err)
	assert.True(ok)
}

func (s *HmacSha256SumSuite) TestVerifyHMACSHA256_OK_empty_payload() {
	assert := s.Assert()
	require := s.Require()

	emptyPayloadSig, err := ComputeHMACSHA256(s.key, []byte(""))
	require.NoError(err)

	ok, err := VerifyHMACSHA256(s.key, []byte(""), emptyPayloadSig)
	assert.NoError(err)
	assert.True(ok)
}

func (s *HmacSha256SumSuite) TestVerifyHMACSHA256_Error_empty_key() {
	assert := s.Assert()

	ok, err := VerifyHMACSHA256([]byte(""), s.payload, s.tag)
	assert.ErrorContains(err, "empty key")
	assert.False(ok)
}

func (s *HmacSha256SumSuite) TestVerifyHMACSHA256_KO_wrong_tag() {
	assert := s.Assert()

	tamperedT := make([]byte, len(s.tag))
	copy(tamperedT, s.tag)
	tamperedT[0] ^= 0x01

	ok, err := VerifyHMACSHA256(s.key, s.payload, tamperedT)
	assert.NoError(err)
	assert.False(ok)
}

func (s *HmacSha256SumSuite) TestVerifyHMACSHA256_KO_wrong_key() {
	assert := s.Assert()

	tamperedK := make([]byte, len(s.key))
	copy(tamperedK, s.key)
	tamperedK[0] ^= 0x01

	ok, err := VerifyHMACSHA256(tamperedK, s.payload, s.tag)
	assert.NoError(err)
	assert.False(ok)
}

func (s *HmacSha256SumSuite) SetupSuite() {
	require := s.Require()

	s.key = []byte("supersecret")
	s.payload = []byte("payload")
	b, err := hex.DecodeString("338500a9b4a336d8981aaa52bbe15b6537d5c5b76665e33459365c6cc83e68ad")
	require.NoError(err)
	s.tag = b
}
