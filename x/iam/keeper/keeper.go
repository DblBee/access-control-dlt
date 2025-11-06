package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"

	"acmain/x/iam/types"
)

type Keeper struct {
	storeService corestore.KVStoreService
	cdc          codec.Codec
	addressCodec address.Codec
	// Address capable of executing a MsgUpdateParams message.
	// Typically, this should be the x/gov module account.
	authority []byte

	Schema collections.Schema
	Params collections.Item[types.Params]

	// Identity management collections
	DIDDocuments         collections.Map[string, types.DIDDocument]
	DIDsByController     collections.KeySet[collections.Pair[string, string]]
	Credentials          collections.Map[string, types.VerifiableCredential]
	RevokedCredentials   collections.Map[string, bool]
	CredentialsBySubject collections.KeySet[collections.Pair[string, string]]
	CredentialsByIssuer  collections.KeySet[collections.Pair[string, string]]
	DeviceKeys           collections.Map[string, types.DeviceKey]
	DeviceKeysByOwner    collections.KeySet[collections.Pair[string, string]]
	DeviceKeysByLocation collections.KeySet[collections.Pair[string, string]]
}

func NewKeeper(
	storeService corestore.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	authority []byte,

) Keeper {
	if _, err := addressCodec.BytesToString(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address %s: %s", authority, err))
	}

	sb := collections.NewSchemaBuilder(storeService)

	k := Keeper{
		storeService: storeService,
		cdc:          cdc,
		addressCodec: addressCodec,
		authority:    authority,

		Params: collections.NewItem(sb, types.ParamsKey, "params", codec.CollValue[types.Params](cdc)),

		// Initialize DID collections
		DIDDocuments: collections.NewMap(
			sb,
			collections.NewPrefix("did:docs"),
			"did_documents",
			collections.StringKey,
			codec.CollValue[types.DIDDocument](cdc),
		),
		DIDsByController: collections.NewKeySet(
			sb,
			collections.NewPrefix("did:ctrl"),
			"dids_by_controller",
			collections.PairKeyCodec(collections.StringKey, collections.StringKey),
		),

		// Initialize credential collections
		Credentials: collections.NewMap(
			sb,
			collections.NewPrefix("vc:main"),
			"credentials",
			collections.StringKey,
			codec.CollValue[types.VerifiableCredential](cdc),
		),
		RevokedCredentials: collections.NewMap(
			sb,
			collections.NewPrefix("vc:revoked"),
			"revoked_credentials",
			collections.StringKey,
			collections.BoolValue,
		),
		CredentialsBySubject: collections.NewKeySet(
			sb,
			collections.NewPrefix("vc:subject"),
			"credentials_by_subject",
			collections.PairKeyCodec(collections.StringKey, collections.StringKey),
		),
		CredentialsByIssuer: collections.NewKeySet(
			sb,
			collections.NewPrefix("vc:issuer"),
			"credentials_by_issuer",
			collections.PairKeyCodec(collections.StringKey, collections.StringKey),
		),

		// Initialize device key collections
		DeviceKeys: collections.NewMap(
			sb,
			collections.NewPrefix("dk:main"),
			"device_keys",
			collections.StringKey,
			codec.CollValue[types.DeviceKey](cdc),
		),
		DeviceKeysByOwner: collections.NewKeySet(
			sb,
			collections.NewPrefix("dk:owner"),
			"device_keys_by_owner",
			collections.PairKeyCodec(collections.StringKey, collections.StringKey),
		),
		DeviceKeysByLocation: collections.NewKeySet(
			sb,
			collections.NewPrefix("dk:loc"),
			"device_keys_by_location",
			collections.PairKeyCodec(collections.StringKey, collections.StringKey),
		),
	}

	schema, err := sb.Build()
	if err != nil {
		panic(err)
	}
	k.Schema = schema

	return k
}

// GetAuthority returns the module's authority.
func (k Keeper) GetAuthority() []byte {
	return k.authority
}

// GetVerifiableCredential retrieves a verifiable credential by ID.
// Returns the credential and a boolean indicating if it was found.
func (k Keeper) GetVerifiableCredential(ctx context.Context, credentialID string) (types.VerifiableCredential, bool) {
	cred, err := k.Credentials.Get(ctx, credentialID)
	if err != nil {
		return types.VerifiableCredential{}, false
	}
	return cred, true
}

// GetCredentialsBySubject retrieves all active credentials for a subject.
// Returns a list of credentials where the subject matches the provided address.
func (k Keeper) GetCredentialsBySubject(ctx context.Context, subjectDID string) ([]types.VerifiableCredential, error) {
	var credentials []types.VerifiableCredential
	err := k.CredentialsBySubject.Walk(ctx, collections.NewPrefixedPairRange[string, string](subjectDID), func(key collections.Pair[string, string]) (stop bool, err error) {
		credID := key.K2()
		cred, err := k.Credentials.Get(ctx, credID)
		if err != nil {
			return true, err
		}
		credentials = append(credentials, cred)
		return false, nil
	})
	return credentials, err
}

// GetDeviceKey retrieves a device's public key information.
// Returns the device key and a boolean indicating if it was found.
func (k Keeper) GetDeviceKey(ctx context.Context, deviceID string) (types.DeviceKey, bool) {
	dk, err := k.DeviceKeys.Get(ctx, deviceID)
	if err != nil {
		return types.DeviceKey{}, false
	}
	return dk, true
}

// VerifyCredentialStatus checks if a credential is active and not revoked.
// Returns true if the credential is valid and can be used for access control.
func (k Keeper) VerifyCredentialStatus(ctx context.Context, credentialID string) (bool, error) {
	cred, err := k.Credentials.Get(ctx, credentialID)
	if err != nil {
		return false, err
	}
	// Check if credential is active and not revoked
	if cred.CredentialStatus == nil {
		return false, nil
	}
	return cred.CredentialStatus.Status == types.CREDENTIAL_STATUS_ACTIVE, nil
}
