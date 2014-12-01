package Iterative

import "ZKP"

type ProverError struct {
}

func (this ProverError) Error() string {
	return "Out of order call"
}

type Prover struct {
	prover *ZKP.Prover
	privateKey *ZKP.PrivateKey
	Notifier struct {
		Proof    chan <- ZKP.Proof
		Error    chan <- ProverError
		Response chan <- ZKP.Response
	}
	proverHelper ZKP.ProverHelper
}

func NewProver(privateKey *ZKP.PrivateKey, proverHelper ZKP.ProverHelper) *Prover {
	return &Prover{privateKey: privateKey, proverHelper: proverHelper}
}

func (this *Prover) NextRound() {
	this.prover = ZKP.NewProver(this.privateKey, this.proverHelper)
	this.Notifier.Proof <- this.prover.ConstructProof()
}

func (this *Prover) Challenge(challenge ZKP.Challenge) {
	if this.prover == nil {
		this.Notifier.Error <- ProverError{}
	} else {
		this.Notifier.Response <- this.prover.Respond(challenge)
	}
}

type VerifierError struct {
	VerificationFailed        bool
	InvalidMessageOrder       bool
	VerifierConstructionError bool
}

func (this VerifierError) Error() string {
	if this.VerificationFailed {
		return "verification failed"
	}
	if this.InvalidMessageOrder {
		return "invalid message order"
	}
	if this.VerifierConstructionError {
		return "verifier construction error"
	}
	return "no error"
}

type Verifier struct {
	verifier *ZKP.Verifier
	counter        uint64
	rounds         uint64
	publicKey      ZKP.PublicKey
	Notifier struct {
		Challenge chan <- ZKP.Challenge
		NextRound chan <- bool
		Error     chan <- VerifierError
		Success   chan <- bool
		Progress  chan <- uint64
	}
	verifierHelper ZKP.VerifierHelper
}

func NewVerifier(publicKey ZKP.PublicKey, rounds uint64, verifierHelper ZKP.VerifierHelper) *Verifier {
	return &Verifier{publicKey: publicKey, rounds: rounds, verifierHelper: verifierHelper}
}

func (this *Verifier) Proof(proof ZKP.Proof) {
	var err error
	this.verifier, err = ZKP.NewVerifier(this.publicKey, proof, this.verifierHelper)
	if err != nil {
		this.Notifier.Error <- VerifierError{VerifierConstructionError: true}
	} else {
		this.Notifier.Challenge <-this.verifier.Challenge
	}
}

func (this *Verifier) Start() {
	this.Notifier.NextRound <- true
}

func (this* Verifier) Response(response ZKP.Response) {
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
