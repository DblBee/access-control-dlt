package keeper

import (
	"acmain/x/iam/types"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	stderrors "errors"

	"cosmossdk.io/collections"
	sdkerrors "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface
// for the provided Keeper.
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

// RegisterDID registers a new Decentralized Identifier with its document
func (k msgServer) RegisterDID(ctx context.Context, msg *types.MsgRegisterDID) (*types.MsgRegisterDIDResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer matches controller (CRITICAL SECURITY CHECK)
	signers, err := k.addressCodec.StringToBytes(msg.Controller)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid controller address")
	}

	// In Cosmos SDK v0.50+, we validate the message signer via the controller field
	// The cosmos.msg.v1.signer annotation ensures msg.Controller is the transaction signer
	if msg.Controller == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "controller address cannot be empty")
	}

	// Additional validation: ensure address is valid
	if len(signers) == 0 {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "controller address is invalid")
	}

	// Validate DID format (H1 FIX)
	if err := types.ValidateDID(msg.Did, msg.DidMethod); err != nil {
		return nil, err
	}

	// Check if DID already exists
	if _, err := k.DIDDocuments.Get(ctx, msg.Did); err == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "DID already registered")
	}

	// Validate public key (H2 FIX)
	if err := types.ValidatePublicKey(msg.PublicKey, msg.KeyType); err != nil {
		return nil, err
	}

	// Get current block time
	timestamp := sdkCtx.BlockTime()

	// Create initial public key
	publicKeyInfo := types.PublicKeyInfo{
		KeyId:      "key-1",
		PublicKey:  msg.PublicKey,
		KeyType:    msg.KeyType,
		Purpose:    "authentication",
		Controller: msg.Controller,
		CreatedAt:  timestamp,
	}

	// Create verification relationship
	verificationRelationship := types.VerificationRelationship{
		RelationshipType: "authentication",
		KeyId:            "key-1",
	}

	// Create DID document
	didDoc := types.DIDDocument{
		Id:                        msg.Did,
		Context:                   []string{"https://www.w3.org/ns/did/v1"},
		Controller:                msg.Controller,
		PublicKeys:                []types.PublicKeyInfo{publicKeyInfo},
		VerificationRelationships: []types.VerificationRelationship{verificationRelationship},
		ServiceEndpoints:          msg.ServiceEndpoints,
		AlsoKnownAs:               msg.AlsoKnownAs,
		CreatedAt:                 timestamp,
		UpdatedAt:                 timestamp,
		Deactivated:               false,
		DidMethod:                 msg.DidMethod,
	}

	// Store DID document
	if err := k.DIDDocuments.Set(ctx, msg.Did, didDoc); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to store DID document")
	}

	// Add to controller index
	if err := k.DIDsByController.Set(ctx, collections.Join(msg.Controller, msg.Did)); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to store DID index")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventDIDRegistered{
		Did:        msg.Did,
		Controller: msg.Controller,
	})

	return &types.MsgRegisterDIDResponse{
		DidDocument: &didDoc,
	}, nil
}

// UpdateDIDDocument updates an existing DID document
func (k msgServer) UpdateDIDDocument(ctx context.Context, msg *types.MsgUpdateDIDDocument) (*types.MsgUpdateDIDDocumentResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Controller)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid controller address")
	}

	// Retrieve DID document
	didDoc, err := k.DIDDocuments.Get(ctx, msg.Did)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "DID document not found")
	}

	// Guard clause: validate sender is controller
	// The cosmos.msg.v1.signer annotation ensures msg.Controller is the transaction signer
	if msg.Controller != didDoc.Controller {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only controller can update DID")
	}

	// Guard clause: check if deactivated
	if didDoc.Deactivated {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "cannot update deactivated DID")
	}

	// Update mutable fields
	didDoc.ServiceEndpoints = msg.ServiceEndpoints
	didDoc.AlsoKnownAs = msg.AlsoKnownAs
	didDoc.UpdatedAt = sdkCtx.BlockTime()

	// Store updated document
	if err := k.DIDDocuments.Set(ctx, msg.Did, didDoc); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to update DID document")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventDIDUpdated{
		Did: msg.Did,
	})

	return &types.MsgUpdateDIDDocumentResponse{
		DidDocument: &didDoc,
	}, nil
}

// DeactivateDID deactivates a DID, preventing further modifications
func (k msgServer) DeactivateDID(ctx context.Context, msg *types.MsgDeactivateDID) (*types.MsgDeactivateDIDResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Controller)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid controller address")
	}

	// Retrieve DID document
	didDoc, err := k.DIDDocuments.Get(ctx, msg.Did)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "DID document not found")
	}

	// Guard clause: validate sender is controller
	// The cosmos.msg.v1.signer annotation ensures msg.Controller is the transaction signer
	if msg.Controller != didDoc.Controller {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only controller can deactivate DID")
	}

	// Mark as deactivated
	didDoc.Deactivated = true
	blockTime := sdkCtx.BlockTime()
	didDoc.DeactivatedAt = &blockTime

	// Store updated document
	if err := k.DIDDocuments.Set(ctx, msg.Did, didDoc); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to deactivate DID")
	}

	// TODO: Emit event when event types are defined

	return &types.MsgDeactivateDIDResponse{}, nil
}

// AddPublicKey adds a new public key to a DID document
func (k msgServer) AddPublicKey(ctx context.Context, msg *types.MsgAddPublicKey) (*types.MsgAddPublicKeyResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Controller)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid controller address")
	}

	// Retrieve DID document
	didDoc, err := k.DIDDocuments.Get(ctx, msg.Did)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "DID document not found")
	}

	// Guard clause: validate sender is controller
	// The cosmos.msg.v1.signer annotation ensures msg.Controller is the transaction signer
	if msg.Controller != didDoc.Controller {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only controller can add keys")
	}

	// Guard clause: check if deactivated
	if didDoc.Deactivated {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "cannot modify deactivated DID")
	}

	// Validate key parameters (H1/H2 FIX)
	if err := types.ValidateKeyID(msg.KeyId); err != nil {
		return nil, err
	}

	if err := types.ValidatePublicKey(msg.PublicKey, msg.KeyType); err != nil {
		return nil, err
	}

	// Check if key ID already exists
	for _, pk := range didDoc.PublicKeys {
		if pk.KeyId == msg.KeyId {
			return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "key ID already exists")
		}
	}

	// Create new public key
	publicKeyInfo := types.PublicKeyInfo{
		KeyId:      msg.KeyId,
		PublicKey:  msg.PublicKey,
		KeyType:    msg.KeyType,
		Purpose:    msg.Purpose,
		Controller: msg.Controller,
		CreatedAt:  sdkCtx.BlockTime(),
	}

	// Add to document
	didDoc.PublicKeys = append(didDoc.PublicKeys, publicKeyInfo)

	// Add verification relationship if not already present
	hasRelationship := false
	for _, rel := range didDoc.VerificationRelationships {
		if rel.KeyId == msg.KeyId && rel.RelationshipType == msg.Purpose {
			hasRelationship = true
			break
		}
	}

	if !hasRelationship {
		didDoc.VerificationRelationships = append(didDoc.VerificationRelationships,
			types.VerificationRelationship{
				RelationshipType: msg.Purpose,
				KeyId:            msg.KeyId,
			})
	}

	didDoc.UpdatedAt = sdkCtx.BlockTime()

	// Store updated document
	if err := k.DIDDocuments.Set(ctx, msg.Did, didDoc); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to update DID document")
	}

	// Emit event
	// TODO: Emit event when event types are defined

	return &types.MsgAddPublicKeyResponse{
		PublicKeyInfo: &publicKeyInfo,
	}, nil
}

// RevokePublicKey revokes a public key from a DID document
func (k msgServer) RevokePublicKey(ctx context.Context, msg *types.MsgRevokePublicKey) (*types.MsgRevokePublicKeyResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Controller)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid controller address")
	}

	// Retrieve DID document
	didDoc, err := k.DIDDocuments.Get(ctx, msg.Did)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "DID document not found")
	}

	// Guard clause: validate sender is controller
	// The cosmos.msg.v1.signer annotation ensures msg.Controller is the transaction signer
	if msg.Controller != didDoc.Controller {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only controller can revoke keys")
	}

	// Find and revoke the key
	keyFound := false
	blockTime := sdkCtx.BlockTime()
	for i, pk := range didDoc.PublicKeys {
		if pk.KeyId == msg.KeyId {
			didDoc.PublicKeys[i].RevokedAt = &blockTime
			keyFound = true
			break
		}
	}

	if !keyFound {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "public key not found")
	}

	didDoc.UpdatedAt = sdkCtx.BlockTime()

	// Store updated document
	if err := k.DIDDocuments.Set(ctx, msg.Did, didDoc); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to update DID document")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventPublicKeyRevoked{
		Did:   msg.Did,
		KeyId: msg.KeyId,
	})

	return &types.MsgRevokePublicKeyResponse{}, nil
}

// IssueCredential issues a new Verifiable Credential
func (k msgServer) IssueCredential(ctx context.Context, msg *types.MsgIssueCredential) (*types.MsgIssueCredentialResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Issuer)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid issuer address")
	}

	// The cosmos.msg.v1.signer annotation ensures msg.Issuer is the transaction signer
	if msg.Issuer == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "issuer address cannot be empty")
	}

	// Validate credential type (H1 FIX)
	if err := types.ValidateCredentialType(msg.CredentialType); err != nil {
		return nil, err
	}

	// Validate subject DID - note: we don't enforce method here as subject could use any DID method
	if msg.Subject == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "subject DID cannot be empty")
	}

	// Validate validity period
	blockTime := sdkCtx.BlockTime()
	validFrom := msg.ValidFrom
	if validFrom == nil {
		validFrom = &blockTime
	}

	if msg.ValidUntil == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "valid_until must be specified")
	}

	if msg.ValidUntil.Before(*validFrom) {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "valid_until must be after valid_from")
	}

	// Generate unique credential ID (deterministic using block height and block time nanos)
	// Note: Block time nanos are deterministic as they're agreed upon by consensus
	credentialID := generateCredentialID(msg.Issuer, msg.Subject, sdkCtx.BlockHeight(), uint32(blockTime.UnixNano()%1000000))

	// 1. Get issuer's DID document
	issuerDID, err := k.DIDDocuments.Get(ctx, msg.Issuer)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "issuer DID not found")
	}

	// 2. Find issuer's assertion key
	var assertionKey *types.PublicKeyInfo
	for i := range issuerDID.PublicKeys {
		if issuerDID.PublicKeys[i].Purpose == "assertionMethod" && issuerDID.PublicKeys[i].RevokedAt == nil {
			assertionKey = &issuerDID.PublicKeys[i]
			break
		}
	}

	if assertionKey == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "issuer has no active assertion key")
	}

	// 3. Create canonical credential hash
	credentialHash := hashCredential(
		msg.Issuer,
		msg.Subject,
		msg.CredentialType,
		msg.Claims,
		validFrom.UnixNano(),
		msg.ValidUntil.UnixNano(),
	)

	// 4. Verify signature
	if err := verifySignature(assertionKey.PublicKey, credentialHash, msg.Signature, assertionKey.KeyType); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "invalid credential signature: "+err.Error())
	}

	// 5. Create proper proof
	proof := types.CredentialProof{
		Type:               getProofType(assertionKey.KeyType),
		CreatedAt:          blockTime,
		VerificationMethod: issuerDID.Id + "#" + assertionKey.KeyId,
		ProofValue:         msg.Signature,
	}

	// Create credential status
	credentialStatus := types.CredentialStatusInfo{
		Status:    types.CREDENTIAL_STATUS_ACTIVE,
		UpdatedAt: blockTime,
	}

	// Create credential subject
	credentialSubject := types.CredentialSubject{
		Id:     msg.Subject,
		Claims: msg.Claims,
	}

	// Create verifiable credential
	vc := types.VerifiableCredential{
		Id:                credentialID,
		Context:           []string{"https://www.w3.org/2018/credentials/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            msg.Issuer,
		IssuedAt:          blockTime,
		CredentialSubject: credentialSubject,
		ValidFrom:         validFrom,
		ValidUntil:        msg.ValidUntil,
		CredentialStatus:  &credentialStatus,
		Proof:             proof,
		CredentialType:    msg.CredentialType,
		Holder:            msg.Subject,
		Metadata:          msg.Metadata,
		RefreshService:    msg.RefreshService,
	}

	// Store credential
	if err := k.Credentials.Set(ctx, credentialID, vc); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to store credential")
	}

	// Add to subject index
	if err := k.CredentialsBySubject.Set(ctx, collections.Join(msg.Subject, credentialID)); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to store subject index")
	}

	// Add to issuer index
	if err := k.CredentialsByIssuer.Set(ctx, collections.Join(msg.Issuer, credentialID)); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to store issuer index")
	}

	// TODO: Emit event when event types are defined

	return &types.MsgIssueCredentialResponse{
		CredentialId:         credentialID,
		VerifiableCredential: &vc,
	}, nil
}

// RevokeCredential revokes a previously issued Verifiable Credential
func (k msgServer) RevokeCredential(ctx context.Context, msg *types.MsgRevokeCredential) (*types.MsgRevokeCredentialResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Issuer)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid issuer address")
	}

	// Retrieve credential
	credential, err := k.Credentials.Get(ctx, msg.CredentialId)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "credential not found")
	}

	// Guard clause: validate sender is issuer
	// The cosmos.msg.v1.signer annotation ensures msg.Issuer is the transaction signer
	if msg.Issuer != credential.Issuer {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only original issuer can revoke credential")
	}

	// Check if already revoked (C4 FIX: proper error handling)
	revoked, err := k.RevokedCredentials.Get(ctx, msg.CredentialId)
	if err != nil && !stderrors.Is(err, collections.ErrNotFound) {
		return nil, sdkerrors.Wrap(err, "failed to check revocation status")
	}
	if revoked {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "credential already revoked")
	}

	// Mark as revoked in permanent record
	if err := k.RevokedCredentials.Set(ctx, msg.CredentialId, true); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to revoke credential")
	}

	// Update credential status
	blockTime := sdkCtx.BlockTime()
	credential.CredentialStatus = &types.CredentialStatusInfo{
		Status:           types.CREDENTIAL_STATUS_REVOKED,
		UpdatedAt:        blockTime,
		RevocationReason: msg.RevocationReason,
	}

	// Store updated credential (immutable record of revocation)
	if err := k.Credentials.Set(ctx, msg.CredentialId, credential); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to update credential")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventCredentialRevoked{
		CredentialId: msg.CredentialId,
		Issuer:       msg.Issuer,
		Reason:       msg.RevocationReason,
	})

	return &types.MsgRevokeCredentialResponse{}, nil
}

// SuspendCredential temporarily suspends a Verifiable Credential
func (k msgServer) SuspendCredential(ctx context.Context, msg *types.MsgSuspendCredential) (*types.MsgSuspendCredentialResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Issuer)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid issuer address")
	}

	// Retrieve credential
	credential, err := k.Credentials.Get(ctx, msg.CredentialId)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "credential not found")
	}

	// Guard clause: validate sender is issuer
	// The cosmos.msg.v1.signer annotation ensures msg.Issuer is the transaction signer
	if msg.Issuer != credential.Issuer {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only issuer can suspend credential")
	}

	// Check if revoked
	if revoked, _ := k.RevokedCredentials.Get(ctx, msg.CredentialId); revoked {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "cannot suspend revoked credential")
	}

	// Update status to suspended
	blockTime := sdkCtx.BlockTime()
	credential.CredentialStatus = &types.CredentialStatusInfo{
		Status:           types.CREDENTIAL_STATUS_SUSPENDED,
		UpdatedAt:        blockTime,
		RevocationReason: msg.SuspensionReason,
	}

	// Store updated credential
	if err := k.Credentials.Set(ctx, msg.CredentialId, credential); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to suspend credential")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventCredentialSuspended{
		CredentialId: msg.CredentialId,
		Issuer:       msg.Issuer,
		Reason:       msg.SuspensionReason,
	})

	return &types.MsgSuspendCredentialResponse{}, nil
}

// ResumeCredential resumes a previously suspended Verifiable Credential
func (k msgServer) ResumeCredential(ctx context.Context, msg *types.MsgResumeCredential) (*types.MsgResumeCredentialResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Issuer)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid issuer address")
	}

	// Retrieve credential
	credential, err := k.Credentials.Get(ctx, msg.CredentialId)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "credential not found")
	}

	// Guard clause: validate sender is issuer
	// The cosmos.msg.v1.signer annotation ensures msg.Issuer is the transaction signer
	if msg.Issuer != credential.Issuer {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only issuer can resume credential")
	}

	// C5 FIX: Check if permanently revoked
	revoked, err := k.RevokedCredentials.Get(ctx, msg.CredentialId)
	if err != nil && !stderrors.Is(err, collections.ErrNotFound) {
		return nil, sdkerrors.Wrap(err, "failed to check revocation status")
	}
	if revoked {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "cannot resume permanently revoked credential")
	}

	// C6 FIX: Nil pointer check before accessing CredentialStatus
	if credential.CredentialStatus == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "credential has no status")
	}

	// Check if suspended
	if credential.CredentialStatus.Status != types.CREDENTIAL_STATUS_SUSPENDED {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "credential is not suspended")
	}

	// Update status back to active
	blockTime := sdkCtx.BlockTime()
	credential.CredentialStatus = &types.CredentialStatusInfo{
		Status:    types.CREDENTIAL_STATUS_ACTIVE,
		UpdatedAt: blockTime,
	}

	// Store updated credential
	if err := k.Credentials.Set(ctx, msg.CredentialId, credential); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to resume credential")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventCredentialResumed{
		CredentialId: msg.CredentialId,
		Issuer:       msg.Issuer,
	})

	return &types.MsgResumeCredentialResponse{}, nil
}

// RegisterDeviceKey registers an IoT device's public key
func (k msgServer) RegisterDeviceKey(ctx context.Context, msg *types.MsgRegisterDeviceKey) (*types.MsgRegisterDeviceKeyResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Owner)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid owner address")
	}

	// The cosmos.msg.v1.signer annotation ensures msg.Owner is the transaction signer
	if msg.Owner == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "owner address cannot be empty")
	}

	// Validate device parameters (H1/H2 FIX)
	if err := types.ValidateDeviceID(msg.DeviceId); err != nil {
		return nil, err
	}

	if err := types.ValidatePublicKey(msg.PublicKey, msg.KeyType); err != nil {
		return nil, err
	}

	if msg.Location == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "location cannot be empty")
	}

	// Check if device already exists
	if _, err := k.DeviceKeys.Get(ctx, msg.DeviceId); err == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "device already registered")
	}

	// Create device key
	blockTime := sdkCtx.BlockTime()
	deviceKey := types.DeviceKey{
		DeviceId:     msg.DeviceId,
		PublicKey:    msg.PublicKey,
		KeyType:      msg.KeyType,
		Owner:        msg.Owner,
		DeviceType:   msg.DeviceType,
		Location:     msg.Location,
		RegisteredAt: blockTime,
		Metadata:     msg.Metadata,
		Active:       true,
	}

	// Store device key
	if err := k.DeviceKeys.Set(ctx, msg.DeviceId, deviceKey); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to store device key")
	}

	// Add to owner index
	if err := k.DeviceKeysByOwner.Set(ctx, collections.Join(msg.Owner, msg.DeviceId)); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to store owner index")
	}

	// Add to location index
	if err := k.DeviceKeysByLocation.Set(ctx, collections.Join(msg.Location, msg.DeviceId)); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to store location index")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventDeviceKeyRegistered{
		DeviceId: msg.DeviceId,
		Owner:    msg.Owner,
		Location: msg.Location,
	})

	return &types.MsgRegisterDeviceKeyResponse{
		DeviceKey: &deviceKey,
	}, nil
}

// RevokeDeviceKey revokes a device's public key
func (k msgServer) RevokeDeviceKey(ctx context.Context, msg *types.MsgRevokeDeviceKey) (*types.MsgRevokeDeviceKeyResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Owner)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid owner address")
	}

	// Retrieve device key
	deviceKey, err := k.DeviceKeys.Get(ctx, msg.DeviceId)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "device key not found")
	}

	// Guard clause: validate sender is owner
	// The cosmos.msg.v1.signer annotation ensures msg.Owner is the transaction signer
	if msg.Owner != deviceKey.Owner {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only owner can revoke device key")
	}

	// Mark as revoked
	blockTime := sdkCtx.BlockTime()
	deviceKey.RevokedAt = &blockTime
	deviceKey.Active = false

	// Store updated device key
	if err := k.DeviceKeys.Set(ctx, msg.DeviceId, deviceKey); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to revoke device key")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventDeviceKeyRevoked{
		DeviceId: msg.DeviceId,
		Owner:    msg.Owner,
		Reason:   msg.RevocationReason,
	})

	return &types.MsgRevokeDeviceKeyResponse{}, nil
}

// RotateDeviceKey rotates a device's public key
func (k msgServer) RotateDeviceKey(ctx context.Context, msg *types.MsgRotateDeviceKey) (*types.MsgRotateDeviceKeyResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify signer address is valid (CRITICAL SECURITY CHECK)
	_, err := k.addressCodec.StringToBytes(msg.Owner)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid owner address")
	}

	// Retrieve device key
	deviceKey, err := k.DeviceKeys.Get(ctx, msg.DeviceId)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "device key not found")
	}

	// Guard clause: validate sender is owner
	// The cosmos.msg.v1.signer annotation ensures msg.Owner is the transaction signer
	if msg.Owner != deviceKey.Owner {
		return nil, sdkerrors.Wrap(errors.ErrUnauthorized, "only owner can rotate device key")
	}

	// Validate new key (H2 FIX)
	if err := types.ValidatePublicKey(msg.NewPublicKey, msg.KeyType); err != nil {
		return nil, err
	}

	// Update key material
	blockTime := sdkCtx.BlockTime()
	deviceKey.PublicKey = msg.NewPublicKey
	deviceKey.KeyType = msg.KeyType
	deviceKey.LastRotationAt = &blockTime

	// Store updated device key
	if err := k.DeviceKeys.Set(ctx, msg.DeviceId, deviceKey); err != nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "failed to rotate device key")
	}

	// Emit event
	sdkCtx.EventManager().EmitTypedEvent(&types.EventDeviceKeyRotated{
		DeviceId: msg.DeviceId,
		Owner:    msg.Owner,
	})

	return &types.MsgRotateDeviceKeyResponse{
		DeviceKey: &deviceKey,
	}, nil
}

// generateCredentialID generates a deterministic unique credential ID
// Uses block height and transaction index to ensure consensus across all nodes
func generateCredentialID(issuer, subject string, blockHeight int64, txIndex uint32) string {
	h := sha256.New()
	h.Write([]byte(issuer))
	h.Write([]byte(subject))
	binary.Write(h, binary.BigEndian, blockHeight)
	binary.Write(h, binary.BigEndian, txIndex)
	return "cred-" + hex.EncodeToString(h.Sum(nil)) // Use full 64 hex chars for uniqueness
}
