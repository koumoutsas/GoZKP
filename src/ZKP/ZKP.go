package ZKP

import "crypto/rand"

type Challenge int

const (
	Left Challenge = iota
	Right Challenge
)

type Cloneable interface {
	clone() *Cloneable
}

type PublicKey interface {
}

type PrivateKey interface {
	PublicKey() *PublicKey
}

type Response interface {
}

type proverHelper interface {
	constructProof() *Proof
	left() *Response
	right() *Response
}

type Proof interface {
}

type Prover struct {
	privateKey *PrivateKey
	proof *Proof
	response *Response
	helper *proverHelper
}

func NewProver(privateKey *PrivateKey) *Prover {
	ret := Prover{privateKey: privateKey}

	return ret;
}

func (this *Prover) ConstructProof() *Proof {
	this.proof = this.helper.constructProof()
	return this.proof
}

func (this *Prover) Respond(challenge Challenge) (ret *Response) {
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
	proof *Proof
	publicKey *PublicKey
	Challenge Challenge
	helper *verifierHelper
}

func newVerifier(publicKey *PublicKey, proof *Proof, helper *verifierHelper) *Verifier {
	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		panic("Unable to get random bit")
	}
	var challenge Challenge
	switch uint8(b[0]) % 2 {
	case 0: challenge = Left
	case 1: challenge = Right
	}
	ret := Verifier{proof, publicKey, challenge, helper}
	return ret;
}

func (this *Verifier) Verify(response Response) bool {
	switch this.challenge {
	case Left: return this.helper.left(this.publicKey, this.proof, response)
	case Right: return this.helper.right(this.publicKey, this.proof, response)
	default: panic("Unknown challenge")
	}
}
