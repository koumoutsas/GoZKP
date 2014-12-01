package Iterative

import (
	"testing"
	"ZKP"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"time"
)

func TestProverError(t *testing.T) {
	assert.Equal(t, "Out of order call", ProverError{}.Error())
}

type proof struct {
}

type response struct {
	value bool
}

type proverHelper struct {
}

func (this proverHelper) Generate() ZKP.Proof {
	return proof{}
}

func (this proverHelper) Left() ZKP.Response {
	return response{true}
}

func (this proverHelper) Right() ZKP.Response {
	return response{false}
}

type publicKey struct {
}

type publicKeyGenerator struct {
}

func (this publicKeyGenerator) Generate() ZKP.PublicKey {
	return new(publicKey)
}

func createProver() (*Prover, error, *ZKP.PrivateKey, ZKP.ProverHelper) {
	privateKey, err := ZKP.NewPrivateKey(publicKeyGenerator{})
	if err != nil {
		return nil, err, nil, nil
	}
	proverHelper := proverHelper{}
	prover := NewProver(privateKey, proverHelper)
	return prover, nil, privateKey, proverHelper
}

func TestNewProver(t *testing.T) {
	assert := assert.New(t)
	prover, err, privateKey, proverHelper := createProver()
	require.Nil(t, err)
	require.NotNil(t, prover)
	assert.Equal(privateKey, prover.privateKey)
	assert.Equal(proverHelper, prover.proverHelper)
}

func TestNextRound(t *testing.T) {
	proofChannel := make(chan ZKP.Proof)
	prover, err, _, _ := createProver()
	require.Nil(t, err)
	prover.Notifier.Proof = proofChannel
	go prover.NextRound()
	select {
	case p := <-proofChannel:
		require.NotNil(t, p)
		_, ok := p.(proof)
		assert.True(t, ok)
	case <-time.After(time.Second):
		t.Fail()
	}
}

func TestChallenge(t *testing.T) {
	errorChannel := make(chan ProverError)
	responseChannel := make(chan ZKP.Response)
	prover, err, _, _ := createProver()
	require.Nil(t, err)
	prover.Notifier.Error = errorChannel
	prover.Notifier.Response = responseChannel
	go prover.Challenge(ZKP.Left)
	select {
	case <-errorChannel:
	case <-responseChannel:
		t.Fail()
	case <-time.After(time.Second):
		t.Fail()
	}
	proofChannel := make(chan ZKP.Proof)
	prover.Notifier.Proof = proofChannel
	go prover.NextRound()
	<-proofChannel
	go prover.Challenge(ZKP.Left)
	select {
	case err := <-errorChannel:
		t.Error(err.Error())
	case r := <-responseChannel:
		require.NotNil(t, r)
		concrete, ok := r.(response)
		require.True(t, ok)
		assert.True(t, concrete.value)
	case <-time.After(time.Second):
		t.Fail()
	}
}

func TestVerifierError(t *testing.T) {
	assert := assert.New(t)
	assert.Equal("verification failed", VerifierError{VerificationFailed:true}.Error())
	assert.Equal("invalid message order", VerifierError{InvalidMessageOrder:true}.Error())
	assert.Equal("verifier construction error", VerifierError{VerifierConstructionError:true}.Error())
	assert.Equal("no error", VerifierError{}.Error())
}

type verifierHelper struct {
}

func (this verifierHelper) Left(publicKey ZKP.PublicKey, proof ZKP.Proof, resp ZKP.Response) bool {
	r, ok := resp.(response)
	if !ok {
		return false
	}
	return r.value
}

func (this verifierHelper) Right(publicKey ZKP.PublicKey, proof ZKP.Proof, resp ZKP.Response) bool {
	r, ok := resp.(response)
	if !ok {
		return false
	}
	return !r.value
}

func createVerifier() (*Verifier, ZKP.PublicKey, uint64, ZKP.VerifierHelper) {
	publicKey := publicKey{}
	rounds := uint64(2)
	helper := verifierHelper{}
	return NewVerifier(publicKey, rounds, helper), publicKey, rounds, helper
}

func TestNewVerifier(t *testing.T) {
	verifier, publicKey, rounds, helper := createVerifier()
	require.NotNil(t, verifier)
	assert := assert.New(t)
	assert.Equal(publicKey, verifier.publicKey)
	assert.Equal(rounds, verifier.rounds)
	assert.Equal(helper, verifier.verifierHelper)
}

func TestProof(t *testing.T) {
	challengeChannel := make(chan ZKP.Challenge)
	verifier, _, _, _ := createVerifier()
	verifier.Notifier.Challenge = challengeChannel
	go verifier.Proof(proof{})
	select {
	case c := <-challengeChannel:
		assert.True(t, c == ZKP.Left || c == ZKP.Right)
	case <-time.After(time.Second):
		t.Fail()
	}
}

func TestStart(t *testing.T) {
	nextRoundChannel := make(chan bool)
	verifier, _, _, _ := createVerifier()
	verifier.Notifier.NextRound = nextRoundChannel
	go verifier.Start()
	select {
	case b := <-nextRoundChannel:
		assert.True(t, b)
	case <-time.After(time.Second):
		t.Fail()
	}
}

func TestResponse(t *testing.T) {
	assert := assert.New(t)
	verifier, _, _, _ := createVerifier()
	errorChannel := make(chan VerifierError)
	verifier.Notifier.Error = errorChannel
	nextRoundChannel := make(chan bool)
	verifier.Notifier.NextRound = nextRoundChannel
	challengeChannel := make(chan ZKP.Challenge)
	verifier.Notifier.Challenge = challengeChannel
	progressChannel := make(chan uint64)
	verifier.Notifier.Progress = progressChannel
	successChannel := make(chan bool)
	verifier.Notifier.Success = successChannel
	go verifier.Response(response{})
	select {
	case err := <-errorChannel:
		assert.True(err.InvalidMessageOrder)
	case <-time.After(time.Second):
		assert.Fail("")
	}
	for i := uint64(0); i < verifier.rounds; i++ {
		go verifier.Proof(proof{})
		go verifier.Response(response{<-challengeChannel == ZKP.Left})
		if i+1 < verifier.rounds {
			select {
			case n := <-nextRoundChannel:
				assert.True(n)
				assert.Equal(i+1, <-progressChannel)
			case p := <-progressChannel:
				assert.Equal(i+1, p)
				assert.True(<-nextRoundChannel)
			case err := <-errorChannel:
				assert.Fail(err.Error())
			case <-time.After(time.Second):
				assert.Fail("")
			}
		} else {
			select {
			case b := <-successChannel:
				assert.True(b)
			case <-time.After(time.Second):
				assert.Fail("")
			}
		}
	}
	go verifier.Proof(proof{})
	go verifier.Response(response{<-challengeChannel != ZKP.Left})
	select {
	case err := <-errorChannel:
		assert.True(err.VerificationFailed)
	case <-time.After(time.Second):
		assert.Fail("")
	}
}
