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

func createPrivateKey() (*PrivateKey, error) {
	return NewPrivateKey(publicKeyGenerator{})
}

func TestNewPrivateKey(t *testing.T) {
	assert := assert.New(t)
	key, err := NewPrivateKey(nil)
	require.NotNil(t, err)
	assert.Equal(NilGenerator, err)
	assert.Nil(key)
	key, err = createPrivateKey()
	assert.Nil(err)
	assert.NotNil(key)
}

func TestPublicKey(t *testing.T) {
	assert := assert.New(t)
	generator := publicKeyGenerator{}
	key, err := NewPrivateKey(generator)
	require.NotNil(t, key)
	require.Nil(t, err)
	k1, err := key.PublicKey()
	require.NotNil(t, k1)
	require.Nil(t, err)
	k2, err := key.PublicKey()
	require.NotNil(t, k2)
	require.Nil(t, err)
	assert.Equal(k1, k2)
	generator.lock()
	key, err = NewPrivateKey(generator)
	require.NotNil(t, key)
	require.Nil(t, err)
	k1, err = key.PublicKey()
	assert.Nil(k1)
	require.NotNil(t, err)
	assert.Equal(ConstructionError, err)
}

type proof struct {
}

type response struct {
	value bool
}

type proverHelper struct {
}

func (this proverHelper) generate() Proof {
	return proof{}
}

func (this proverHelper) left() Response {
	return response{true}
}

func (this proverHelper) right() Response {
	return response{false}
}

func TestNewProver(t *testing.T) {
	assert := assert.New(t)
	privateKey, err := createPrivateKey()
	require.Nil(t, err)
	proverHelper := proverHelper{}
	prover := NewProver(privateKey, proverHelper)
	require.NotNil(t, prover)
	assert.Equal(privateKey, prover.privateKey)
	assert.Equal(proverHelper, prover.helper)
}

func TestConstructProof(t *testing.T) {
	assert := assert.New(t)
	privateKey, err := createPrivateKey()
	require.Nil(t, err)
	proverHelper := proverHelper{}
	prover := NewProver(privateKey, proverHelper)
	require.NotNil(t, prover)
	assert.NotNil(prover.ConstructProof())
}

func TestRepond(t *testing.T) {
	assert := assert.New(t)
	privateKey, err := createPrivateKey()
	require.Nil(t, err)
	proverHelper := proverHelper{}
	prover := NewProver(privateKey, proverHelper)
	r := prover.Respond(Left)
	require.NotNil(t, r)
	assert.True(r.(response).value)
	r = prover.Respond(Right)
	require.NotNil(t, r)
	assert.False(r.(response).value)
}

type verifierHelper struct {
}

func (this verifierHelper) left(publicKey PublicKey, proof Proof, r Response) bool {
	return r.(response).value
}

func (this verifierHelper) right(publicKey PublicKey, proof Proof, r Response) bool {
	return !r.(response).value
}

func TestVerify(t *testing.T) {
	privateKey, err := createPrivateKey()
	require.Nil(t, err)
	publicKey, err := privateKey.PublicKey()
	require.Nil(t, err)
	proof := proof{}
	proverHelper := proverHelper{}
	verifierHelper := verifierHelper{}
	for i := 0; i < 100; i++ {
		prover := NewProver(privateKey, proverHelper)
		verifier, err := NewVerifier(publicKey, proof, verifierHelper)
		require.Nil(t, err)
		assert.True(t, verifier.Verify(prover.Respond(verifier.Challenge)))
	}
}
