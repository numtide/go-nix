package nixbase32

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	testBuf = []byte{
		0xd8, 0x6b, 0x33, 0x92, 0xc1, 0x20, 0x2e, 0x8f,
		0xf5, 0xa4, 0x23, 0xb3, 0x02, 0xe6, 0x28, 0x4d,
		0xb7, 0xf8, 0xf4, 0x35, 0xea, 0x9f, 0x39, 0xb5,
		0xb1, 0xb2, 0x0f, 0xd3, 0xac, 0x36, 0xdf, 0xcb,
	}
	testBase32 = "1jyz6snd63xjn6skk7za6psgidsd53k05cr3lksqybi0q6936syq"
)

func TestEncode(t *testing.T) {
	assert.Equal(t, testBase32, EncodeToString(testBuf))
}

func TestDecode(t *testing.T) {
	b, err := DecodeString(testBase32)

	if assert.NoError(t, err) {
		assert.Equal(t, testBuf, b)
	}
}