package hmac

import (
	"bytes"
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

//
//	RFC4231
//

func (s *HmacSha256SumSuite) TestRFC4231_AllVectors_SHA256() {
	assert := s.Assert()
	require := s.Require()

	// Each case from RFC 4231; expectedLenBytes=16 for the truncated case (Test Case 5).
	cases := []struct {
		name             string
		key              []byte
		data             []byte
		expectedHex      string
		expectedLenBytes int
	}{
		{
			name:             "TC1_short_key_HiThere",
			key:              bytes.Repeat([]byte{0x0b}, 20),
			data:             []byte("Hi There"),
			expectedHex:      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
			expectedLenBytes: 32,
		},
		{
			name:             "TC2_key_Jefe_string_data",
			key:              []byte("Jefe"),
			data:             []byte("what do ya want for nothing?"),
			expectedHex:      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
			expectedLenBytes: 32,
		},
		{
			name:             "TC3_aa20_key_dd50_data",
			key:              bytes.Repeat([]byte{0xaa}, 20),
			data:             bytes.Repeat([]byte{0xdd}, 50),
			expectedHex:      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
			expectedLenBytes: 32,
		},
		{
			name: "TC4_incrementing_key_cd50_data",
			key: func() []byte {
				// 0x01..0x19 (25 bytes)
				k := make([]byte, 25)
				for i := 0; i < 25; i++ {
					k[i] = byte(i + 1)
				}
				return k
			}(),
			data:             bytes.Repeat([]byte{0xcd}, 50),
			expectedHex:      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
			expectedLenBytes: 32,
		},
		{
			name:             "TC5_truncated_to_128_bits",
			key:              bytes.Repeat([]byte{0x0c}, 20),
			data:             []byte("Test With Truncation"),
			expectedHex:      "a3b6167473100ee06e0c796c2955552b", // 16 bytes (128-bit truncation)
			expectedLenBytes: 16,
		},
		{
			name:             "TC6_large_key_hash_key_first",
			key:              bytes.Repeat([]byte{0xaa}, 131),
			data:             []byte("Test Using Larger Than Block-Size Key - Hash Key First"),
			expectedHex:      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
			expectedLenBytes: 32,
		},
		{
			name:             "TC7_large_key_large_data",
			key:              bytes.Repeat([]byte{0xaa}, 131),
			data:             []byte("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
			expectedHex:      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
			expectedLenBytes: 32,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			want, err := hex.DecodeString(tc.expectedHex)
			require.NoError(err)

			got, err := ComputeHMACSHA256(tc.key, tc.data)
			require.NoError(err)

			// For the truncated case, compare only the leading expectedLenBytes.
			if tc.expectedLenBytes < len(got) {
				got = got[:tc.expectedLenBytes]
			}
			assert.Equal(want, got, "RFC4231 %s mismatch", tc.name)

			// Only call Verify when the full 32-byte tag is expected.
			if tc.expectedLenBytes == 32 {
				ok, err := VerifyHMACSHA256(tc.key, tc.data, want)
				require.NoError(err)
				assert.True(ok, "VerifyHMACSHA256 failed for %s", tc.name)
			}
		})
	}
}
