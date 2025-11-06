package keeper

import (
	"acmain/x/iam/types"
	"context"
	"time"

	"cosmossdk.io/collections"
	sdkerrors "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

var _ types.QueryServer = queryServer{}

// NewQueryServerImpl returns an implementation of the QueryServer interface
// for the provided Keeper.
func NewQueryServerImpl(k Keeper) types.QueryServer {
	return queryServer{k}
}

type queryServer struct {
	k Keeper
}

// DID queries a DID document by its identifier
func (qs queryServer) DID(ctx context.Context, req *types.QueryDIDRequest) (*types.QueryDIDResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.Did == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "DID cannot be empty")
	}

	didDoc, err := qs.k.DIDDocuments.Get(ctx, req.Did)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "DID document not found")
	}

	return &types.QueryDIDResponse{
		DidDocument: &didDoc,
	}, nil
}

// DIDs queries all DID documents with optional filtering
func (qs queryServer) DIDs(ctx context.Context, req *types.QueryDIDsRequest) (*types.QueryDIDsResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	var didDocuments []types.DIDDocument

	// Iterate through all DIDs
	iter, err := qs.k.DIDDocuments.Iterate(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		val, err := iter.Value()
		if err != nil {
			return nil, err
		}

		// Apply filters
		if req.DidMethod != types.DID_METHOD_UNSPECIFIED && val.DidMethod != req.DidMethod {
			continue
		}

		if req.DeactivatedOnly && !val.Deactivated {
			continue
		}

		didDocuments = append(didDocuments, val)
	}

	return &types.QueryDIDsResponse{
		DidDocuments: didDocuments,
	}, nil
}

// DIDsByController queries all DIDs controlled by an address
func (qs queryServer) DIDsByController(ctx context.Context, req *types.QueryDIDsByControllerRequest) (*types.QueryDIDsByControllerResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.Controller == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "controller cannot be empty")
	}

	var didDocuments []types.DIDDocument

	// Iterate through DIDs with prefix filter for this controller
	prefix := collections.NewPrefixedPairRange[string, string](req.Controller)
	iter, err := qs.k.DIDsByController.Iterate(ctx, prefix)
	if err != nil {
		// No DIDs for this controller
		return &types.QueryDIDsByControllerResponse{
			DidDocuments: []types.DIDDocument{},
		}, nil
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		pair, err := iter.Key()
		if err != nil {
			return nil, err
		}

		did := pair.K2()

		didDoc, err := qs.k.DIDDocuments.Get(ctx, did)
		if err != nil {
			continue // Skip if document not found
		}

		didDocuments = append(didDocuments, didDoc)
	}

	return &types.QueryDIDsByControllerResponse{
		DidDocuments: didDocuments,
	}, nil
}

// Credential queries a verifiable credential by its identifier
func (qs queryServer) Credential(ctx context.Context, req *types.QueryCredentialRequest) (*types.QueryCredentialResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.CredentialId == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "credential_id cannot be empty")
	}

	credential, err := qs.k.Credentials.Get(ctx, req.CredentialId)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "credential not found")
	}

	return &types.QueryCredentialResponse{
		VerifiableCredential: &credential,
	}, nil
}

// CredentialsBySubject queries all credentials for a given subject DID
func (qs queryServer) CredentialsBySubject(ctx context.Context, req *types.QueryCredentialsBySubjectRequest) (*types.QueryCredentialsBySubjectResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.Subject == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "subject cannot be empty")
	}

	var credentials []types.VerifiableCredential

	// Iterate through credentials with prefix filter for this subject
	prefix := collections.NewPrefixedPairRange[string, string](req.Subject)
	iter, err := qs.k.CredentialsBySubject.Iterate(ctx, prefix)
	if err != nil {
		// No credentials for this subject
		return &types.QueryCredentialsBySubjectResponse{
			VerifiableCredentials: []types.VerifiableCredential{},
		}, nil
	}
	defer iter.Close()

	now := time.Now()

	for ; iter.Valid(); iter.Next() {
		pair, err := iter.Key()
		if err != nil {
			return nil, err
		}

		credID := pair.K2()

		credential, err := qs.k.Credentials.Get(ctx, credID)
		if err != nil {
			continue // Skip if credential not found
		}

		// Apply filters
		if req.CredentialType != types.CREDENTIAL_TYPE_UNSPECIFIED && credential.CredentialType != req.CredentialType {
			continue
		}

		// Check expiration filter
		if !req.IncludeExpired && credential.ValidUntil != nil {
			if now.After(*credential.ValidUntil) {
				continue
			}
		}

		credentials = append(credentials, credential)
	}

	return &types.QueryCredentialsBySubjectResponse{
		VerifiableCredentials: credentials,
	}, nil
}

// CredentialsByIssuer queries all credentials issued by a given address
func (qs queryServer) CredentialsByIssuer(ctx context.Context, req *types.QueryCredentialsByIssuerRequest) (*types.QueryCredentialsByIssuerResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.Issuer == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "issuer cannot be empty")
	}

	var credentials []types.VerifiableCredential
	totalIssued := uint64(0)

	// Iterate through credentials with prefix filter for this issuer
	prefix := collections.NewPrefixedPairRange[string, string](req.Issuer)
	iter, err := qs.k.CredentialsByIssuer.Iterate(ctx, prefix)
	if err != nil {
		// No credentials for this issuer
		return &types.QueryCredentialsByIssuerResponse{
			VerifiableCredentials: []types.VerifiableCredential{},
			TotalIssued:           0,
		}, nil
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		pair, err := iter.Key()
		if err != nil {
			return nil, err
		}

		credID := pair.K2()

		credential, err := qs.k.Credentials.Get(ctx, credID)
		if err != nil {
			continue // Skip if credential not found
		}

		totalIssued++

		// Apply credential type filter
		if req.CredentialType != types.CREDENTIAL_TYPE_UNSPECIFIED && credential.CredentialType != req.CredentialType {
			continue
		}

		credentials = append(credentials, credential)
	}

	return &types.QueryCredentialsByIssuerResponse{
		VerifiableCredentials: credentials,
		TotalIssued:           totalIssued,
	}, nil
}

// IsCredentialValid checks if a credential is currently valid
func (qs queryServer) IsCredentialValid(ctx context.Context, req *types.QueryIsCredentialValidRequest) (*types.QueryIsCredentialValidResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.CredentialId == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "credential_id cannot be empty")
	}

	credential, err := qs.k.Credentials.Get(ctx, req.CredentialId)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "credential not found")
	}

	// Determine check time
	checkTime := time.Now()
	if req.AtTimestamp != nil {
		checkTime = *req.AtTimestamp
	}

	// Check if revoked
	if revoked, _ := qs.k.RevokedCredentials.Get(ctx, req.CredentialId); revoked {
		return &types.QueryIsCredentialValidResponse{
			Valid:     false,
			Reason:    "revoked",
			Status:    types.CREDENTIAL_STATUS_REVOKED,
			ExpiresAt: credential.ValidUntil,
		}, nil
	}

	// Check status
	if credential.CredentialStatus != nil {
		if credential.CredentialStatus.Status == types.CREDENTIAL_STATUS_REVOKED {
			return &types.QueryIsCredentialValidResponse{
				Valid:     false,
				Reason:    "revoked",
				Status:    types.CREDENTIAL_STATUS_REVOKED,
				ExpiresAt: credential.ValidUntil,
			}, nil
		}

		if credential.CredentialStatus.Status == types.CREDENTIAL_STATUS_SUSPENDED {
			return &types.QueryIsCredentialValidResponse{
				Valid:     false,
				Reason:    "suspended",
				Status:    types.CREDENTIAL_STATUS_SUSPENDED,
				ExpiresAt: credential.ValidUntil,
			}, nil
		}
	}

	// Check validity window
	if credential.ValidFrom != nil && checkTime.Before(*credential.ValidFrom) {
		return &types.QueryIsCredentialValidResponse{
			Valid:     false,
			Reason:    "not yet valid",
			Status:    types.CREDENTIAL_STATUS_ACTIVE,
			ExpiresAt: credential.ValidUntil,
		}, nil
	}

	if credential.ValidUntil != nil && checkTime.After(*credential.ValidUntil) {
		return &types.QueryIsCredentialValidResponse{
			Valid:     false,
			Reason:    "expired",
			Status:    types.CREDENTIAL_STATUS_EXPIRED,
			ExpiresAt: credential.ValidUntil,
		}, nil
	}

	// Credential is valid
	return &types.QueryIsCredentialValidResponse{
		Valid:     true,
		Reason:    "valid",
		Status:    types.CREDENTIAL_STATUS_ACTIVE,
		ExpiresAt: credential.ValidUntil,
	}, nil
}

// DeviceKey queries a device's public key by device ID
func (qs queryServer) DeviceKey(ctx context.Context, req *types.QueryDeviceKeyRequest) (*types.QueryDeviceKeyResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.DeviceId == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "device_id cannot be empty")
	}

	deviceKey, err := qs.k.DeviceKeys.Get(ctx, req.DeviceId)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "device key not found")
	}

	return &types.QueryDeviceKeyResponse{
		DeviceKey: &deviceKey,
	}, nil
}

// DeviceKeysByOwner queries all device keys owned by an address
func (qs queryServer) DeviceKeysByOwner(ctx context.Context, req *types.QueryDeviceKeysByOwnerRequest) (*types.QueryDeviceKeysByOwnerResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.Owner == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "owner cannot be empty")
	}

	var deviceKeys []types.DeviceKey

	// Iterate through device keys with prefix filter for this owner
	prefix := collections.NewPrefixedPairRange[string, string](req.Owner)
	iter, err := qs.k.DeviceKeysByOwner.Iterate(ctx, prefix)
	if err != nil {
		// No devices for this owner
		return &types.QueryDeviceKeysByOwnerResponse{
			DeviceKeys: []types.DeviceKey{},
		}, nil
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		pair, err := iter.Key()
		if err != nil {
			return nil, err
		}

		deviceID := pair.K2()

		deviceKey, err := qs.k.DeviceKeys.Get(ctx, deviceID)
		if err != nil {
			continue // Skip if device not found
		}

		// Apply filters
		if req.DeviceType != "" && deviceKey.DeviceType != req.DeviceType {
			continue
		}

		if !req.IncludeInactive && !deviceKey.Active {
			continue
		}

		deviceKeys = append(deviceKeys, deviceKey)
	}

	return &types.QueryDeviceKeysByOwnerResponse{
		DeviceKeys: deviceKeys,
	}, nil
}

// DeviceKeysByLocation queries all device keys at a given location
func (qs queryServer) DeviceKeysByLocation(ctx context.Context, req *types.QueryDeviceKeysByLocationRequest) (*types.QueryDeviceKeysByLocationResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.Location == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "location cannot be empty")
	}

	var deviceKeys []types.DeviceKey

	// Iterate through device keys with prefix filter for this location
	prefix := collections.NewPrefixedPairRange[string, string](req.Location)
	iter, err := qs.k.DeviceKeysByLocation.Iterate(ctx, prefix)
	if err != nil {
		// No devices at this location
		return &types.QueryDeviceKeysByLocationResponse{
			DeviceKeys: []types.DeviceKey{},
			TotalCount: 0,
		}, nil
	}
	defer iter.Close()

	totalCount := uint64(0)
	for ; iter.Valid(); iter.Next() {
		pair, err := iter.Key()
		if err != nil {
			return nil, err
		}

		deviceID := pair.K2()

		deviceKey, err := qs.k.DeviceKeys.Get(ctx, deviceID)
		if err != nil {
			continue // Skip if device not found
		}

		totalCount++

		// Apply filters
		if req.DeviceType != "" && deviceKey.DeviceType != req.DeviceType {
			continue
		}

		if !req.IncludeInactive && !deviceKey.Active {
			continue
		}

		deviceKeys = append(deviceKeys, deviceKey)
	}

	return &types.QueryDeviceKeysByLocationResponse{
		DeviceKeys: deviceKeys,
		TotalCount: totalCount,
	}, nil
}

// PublicKey queries a specific public key from a DID document
func (qs queryServer) PublicKey(ctx context.Context, req *types.QueryPublicKeyRequest) (*types.QueryPublicKeyResponse, error) {
	if req == nil {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "request cannot be nil")
	}

	if req.Did == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "did cannot be empty")
	}

	if req.KeyId == "" {
		return nil, sdkerrors.Wrap(errors.ErrInvalidRequest, "key_id cannot be empty")
	}

	didDoc, err := qs.k.DIDDocuments.Get(ctx, req.Did)
	if err != nil {
		return nil, sdkerrors.Wrap(errors.ErrNotFound, "DID document not found")
	}

	// Find the key
	for _, pk := range didDoc.PublicKeys {
		if pk.KeyId == req.KeyId {
			return &types.QueryPublicKeyResponse{
				PublicKeyInfo: &pk,
			}, nil
		}
	}

	return nil, sdkerrors.Wrap(errors.ErrNotFound, "public key not found")
}

// Params returns the module parameters
func (qs queryServer) Params(ctx context.Context, _ *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	params, err := qs.k.Params.Get(ctx)
	if err != nil {
		return nil, err
	}

	return &types.QueryParamsResponse{
		Params: params,
	}, nil
}
