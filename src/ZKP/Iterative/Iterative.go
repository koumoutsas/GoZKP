package Iterative

import (
	"ZKP"
	"errors"
)

type ProverNotifier struct {
	Proof    chan <- Proof
	Err      chan <- error
	Response chan <- Response
}

type ProverConstructor interface {
	ConstructProver() *ZKP.Prover
}

type Prover struct {
	prover *ZKP.Prover
	privateKey *ZKP.PrivateKey
	Notifier ProverNotifier
	proverConstructor *ProverConstructor
}

func NewProver(privateKey *ZKP.PrivateKey, proverConstructor *ProverConstructor) *Prover {
	return Prover{privateKey: privateKey, proverConstructor: proverConstructor}
}

func (this *Prover) NextRound() {
	this.prover = this.proverConstructor.ConstructProver()
	this.notifier.Proof <- this.prover.ConstructProof()
}

func (this *Prover) Challenge(challenge ZKP.Challenge) {
	if this.prover == nil {
		this.notifier.Err <- errors.New("Out of order call")
	} else {
		this.notifier.Response <- this.prover.Respond(challenge)
	}
}

type VerifierError int

const (
	VerificationFailed VerifierError = iota
	InvalidMessageOrder
)

type VerifierConstructor interface {
	ConstructVerifier(publicKey *ZKP.PublicKey, proof *ZKP.Proof) *ZKP.Verifier
}

type VerifierNotifier struct {
	Challenge chan <- ZKP.Challenge
	NextRound chan <- bool
	Error     chan <- VerifierError
	Success   chan <- bool
	Progress  chan <- uint64
}

type Verifier struct {
	verifier *ZKP.Verifier
	counter  uint64
	rounds   uint64
	publicKey *ZKP.PublicKey
	Notifier VerifierNotifier
	verifierConstructor *VerifierConstructor
}

func NewVerifier(publicKey *ZKP.PublicKey, rounds uint64, verifierConstructor *VerifierConstructor) *Verifier {
	return Verifier{publicKey: publicKey, rounds: rounds, verifierConstructor: verifierConstructor}
}

func (this *Verifier) Proof(proof *ZKP.Proof) {
	this.verifier = this.verifierConstructor.ConstructVerifier(this.publicKey, proof)
	this.Notifier.Challenge <-this.verifier.Challenge
}

func (this *Verifier) Start() {
	this.Notifier.NextRound <- true
}

func (this* Verifier) Response(response *ZKP.Response) {
	if this.verifier == nil {
		this.Notifier.Error <- InvalidMessageOrder
		return
	}
	if this.verifier.Verify(response) {
		this.counter++
		if this.counter == this.rounds {
			this.Notifier.Success <- true
		} else {
			this.Notifier.Progress <- this.counter
			this.Notifier.NextRound <- true
		}
	} else {
		this.Notifier.Error <- VerificationFailed
	}
}
