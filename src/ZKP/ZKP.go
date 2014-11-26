package ZKP

import "crypto/rand"
import "errors"

var (
	NilGenerator      = errors.New("nil generator")
	ConstructionError = errors.New("construction error")
)

type Challenge int

const (
	Left Challenge = iota
	Right Challenge = iota
)

type PublicKey interface {
}

type PublicKeyGenerator interface {
	generate() PublicKey
}

type PrivateKey struct {
	publicKey PublicKey
	generator PublicKeyGenerator
}

func NewPrivateKey(generator PublicKeyGenerator) (*PrivateKey, error) {
	if generator == nil {
		return nil, NilGenerator
	}
	return &PrivateKey{generator: generator}, nil
}

func (this *PrivateKey) PublicKey() (PublicKey, error) {
	if this.publicKey == nil {
		if this.generator == nil {
			return nil, NilGenerator
		}
		this.publicKey = this.generator.generate()
		if this.publicKey == nil {
			return nil, ConstructionError
		}
	}
	return this.publicKey, nil
}

type Response interface {
}

type proverHelper interface {
	constructProof() Proof
	left() Response
	right() Response
}

type Proof interface {
}

type Prover struct {
	privateKey *PrivateKey
	proof    Proof
	response Response
	helper   proverHelper
}

func NewProver(privateKey *PrivateKey) *Prover {
	return &Prover{privateKey: privateKey}
}

func (this *Prover) ConstructProof() Proof {
	this.proof = this.helper.constructProof()
	return this.proof
}

func (this *Prover) Respond(challenge Challenge) (ret Response) {
	switch challenge{
	case Left: ret = this.helper.left()
	case Right: ret = this.helper.right()
	default: panic("Unknown challenge")
	}
	this.response = ret
	return
}

type verifierHelper interface {
	left(publicKey PublicKey, proof Proof, response Response) bool
	right(publicKey PublicKey, proof Proof, response Response) bool
}

type Verifier struct {
	proof     Proof
	publicKey PublicKey
	Challenge Challenge
	helper    verifierHelper
}

func newVerifier(publicKey PublicKey, proof Proof, helper verifierHelper) (*Verifier, error) {
	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		return nil, ConstructionError
	}
	var challenge Challenge
	switch uint8(b[0]) % 2 {
	case 0: challenge = Left
	case 1: challenge = Right
	}
	return &Verifier{proof, publicKey, challenge, helper}, nil
}

func (this *Verifier) Verify(response Response) bool {
	switch this.Challenge {
	case Left: return this.helper.left(this.publicKey, this.proof, response)
	case Right: return this.helper.right(this.publicKey, this.proof, response)
	default: panic("Unknown challenge")
	}
}
