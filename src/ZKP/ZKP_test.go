package ZKP

import "testing"
import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publicKey struct {
}

type publicKeyGenerator struct {
	locked bool
}

func (this publicKeyGenerator) generate() PublicKey {
	if this.locked {
		return nil
	}
	return new(publicKey)
}

func (this *publicKeyGenerator) lock() {
	this.locked = true
}

func (this *publicKeyGenerator) unlock() {
	this.locked = false
}

func TestNewPrivateKey(t *testing.T) {
	assert := assert.New(t)
	key, err := NewPrivateKey(nil)
	require.NotNil(t, err)
	assert.Equal(NilGenerator, err)
	assert.Nil(key)
	key, err = NewPrivateKey(publicKeyGenerator{})
	assert.Nil(err)
	assert.NotNil(key)
}
