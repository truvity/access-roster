package driver

import (
	"context"

	"connectrpc.com/connect"

	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
)

// The PIN release calls of the port (ADR 0006, "Touch and PIN"), as a store without a card answers them. A software
// store has no PIN and is never locked, so it has nothing to release and nothing to be released to; and it attests
// nothing (Capabilities says attests false). key@ reads these refusals as "this node takes no part in the PIN
// release": its slot map entry has no attestation, and a peer refuses a request that names it.
const (
	reasonUnlocked      = "unlocked"
	reasonNoPIN         = "no_pin"
	reasonNoAttestation = "no_attestation"
)

// Attest refuses: a software key has no attestation.
func (*Service) Attest(ctx context.Context, _ *connect.Request[keystorev2alpha1.AttestRequest]) (*connect.Response[keystorev2alpha1.AttestResponse], error) {
	return nil, refuse(ctx, "Attest", connect.CodeFailedPrecondition, reasonNoAttestation, "")
}

// VerifyAttestation refuses: the software store holds no attestation anchors.
func (*Service) VerifyAttestation(ctx context.Context, _ *connect.Request[keystorev2alpha1.VerifyAttestationRequest]) (*connect.Response[keystorev2alpha1.VerifyAttestationResponse], error) {
	return nil, refuse(ctx, "VerifyAttestation", connect.CodeFailedPrecondition, reasonNoAttestation, "")
}

// BeginPinRelease refuses as an unlocked store does: there is no PIN to wait for.
func (*Service) BeginPinRelease(ctx context.Context, _ *connect.Request[keystorev2alpha1.BeginPinReleaseRequest]) (*connect.Response[keystorev2alpha1.BeginPinReleaseResponse], error) {
	return nil, refuse(ctx, "BeginPinRelease", connect.CodeFailedPrecondition, reasonUnlocked, "")
}

// SealPin refuses: there is no PIN to seal.
func (*Service) SealPin(ctx context.Context, _ *connect.Request[keystorev2alpha1.SealPinRequest]) (*connect.Response[keystorev2alpha1.SealPinResponse], error) {
	return nil, refuse(ctx, "SealPin", connect.CodeFailedPrecondition, reasonNoPIN, "")
}

// FinishPinRelease refuses as an unlocked store does.
func (*Service) FinishPinRelease(ctx context.Context, _ *connect.Request[keystorev2alpha1.FinishPinReleaseRequest]) (*connect.Response[keystorev2alpha1.FinishPinReleaseResponse], error) {
	return nil, refuse(ctx, "FinishPinRelease", connect.CodeFailedPrecondition, reasonUnlocked, "")
}
