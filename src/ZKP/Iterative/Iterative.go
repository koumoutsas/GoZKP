package Iterative

import "ZKP"

type ProverConstructor interface {
	ConstructProver() *ZKP.Prover
}

type ProverError struct {
}

func (this ProverError) Error() string {
	return "Out of order call"
}

type Prover struct {
	prover *ZKP.Prover
	privateKey *ZKP.PrivateKey
	Notifier struct {
		Proof    chan <- Proof
		Error    chan <- ProverError
		Response chan <- Response
	}
	proverConstructor *ProverConstructor
}

func NewProver(privateKey *ZKP.PrivateKey, proverConstructor *ProverConstructor) *Prover {
	return &Prover{privateKey: privateKey, proverConstructor: proverConstructor}
}

func (this *Prover) NextRound() {
	this.prover = this.proverConstructor.ConstructProver()
	this.notifier.Proof <- this.prover.ConstructProof()
}

func (this *Prover) Challenge(challenge ZKP.Challenge) {
	if this.prover == nil {
		this.notifier.Error <- ProverError{}
	} else {
		this.notifier.Response <- this.prover.Respond(challenge)
	}
}

type VerifierError struct {
	VerificationFailed  bool
	InvalidMessageOrder bool
}

func (this VerifierError) Error() string {
	if this.VerificationFailed {
		return "verification failed"
	}
	if this.InvalidMessageOrder {
		return "invalid message order"
	}
	return "no error"
}

type VerifierConstructor interface {
	ConstructVerifier(publicKey *ZKP.PublicKey, proof *ZKP.Proof) *ZKP.Verifier
}

type Verifier struct {
	verifier *ZKP.Verifier
	counter  uint64
	rounds   uint64
	publicKey *ZKP.PublicKey
	Notifier struct {
		Challenge chan <- ZKP.Challenge
		NextRound chan <- bool
		Error     chan <- VerifierError
		Success   chan <- bool
		Progress  chan <- uint64
	}
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
		this.Notifier.Error <- VerifierError{InvalidMessageOrder: true}
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
		this.Notifier.Error <- VerifierError{VerificationFailed: true}
	}
}
