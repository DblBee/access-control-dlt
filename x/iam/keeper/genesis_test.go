package keeper_test

import (
	"testing"
	"time"

	"acmain/x/iam/types"

	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),
	}

	f := initFixture(t)
	err := f.keeper.InitGenesis(f.ctx, genesisState)
	require.NoError(t, err)
	got, err := f.keeper.ExportGenesis(f.ctx)
	require.NoError(t, err)
	require.NotNil(t, got)

	require.EqualExportedValues(t, genesisState.Params, got.Params)
}

func TestGenesisWithCollections(t *testing.T) {
	now := time.Now()

	// Create test data with all collections
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),
		DidDocuments: []types.DIDDocument{
			{
				Id:         "did:acmain:test1",
				Controller: "cosmos1test1controller",
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			{
				Id:         "did:acmain:test2",
				Controller: "cosmos1test2controller",
				CreatedAt:  now,
				UpdatedAt:  now,
			},
		},
		Credentials: []types.VerifiableCredential{
			{
				Id:       "cred1",
				Issuer:   "cosmos1issuer",
				IssuedAt: now,
				CredentialSubject: types.CredentialSubject{
					Id: "did:acmain:test1",
				},
				Proof: types.CredentialProof{
					Type: "Ed25519Signature2020",
				},
			},
			{
				Id:       "cred2",
				Issuer:   "cosmos1issuer2",
				IssuedAt: now,
				CredentialSubject: types.CredentialSubject{
					Id: "did:acmain:test2",
				},
				Proof: types.CredentialProof{
					Type: "Ed25519Signature2020",
				},
			},
		},
		RevokedCredentialIds: []string{"cred3", "cred4"},
		DeviceKeys: []types.DeviceKey{
			{
				DeviceId:     "device1",
				PublicKey:    []byte("pubkey1"),
				KeyType:      types.KEY_TYPE_ED25519,
				Owner:        "cosmos1owner1",
				DeviceType:   "smart_lock",
				Location:     "building_a",
				RegisteredAt: now,
				Active:       true,
			},
			{
				DeviceId:     "device2",
				PublicKey:    []byte("pubkey2"),
				KeyType:      types.KEY_TYPE_SECP256K1,
				Owner:        "cosmos1owner2",
				DeviceType:   "sensor",
				Location:     "building_b",
				RegisteredAt: now,
				Active:       true,
			},
		},
	}

	f := initFixture(t)

	// Test InitGenesis
	err := f.keeper.InitGenesis(f.ctx, genesisState)
	require.NoError(t, err)

	// Verify DID documents were imported
	for _, expectedDoc := range genesisState.DidDocuments {
		doc, found := f.keeper.DIDDocuments.Get(f.ctx, expectedDoc.Id)
		require.NoError(t, found)
		require.Equal(t, expectedDoc.Id, doc.Id)
		require.Equal(t, expectedDoc.Controller, doc.Controller)
	}

	// Verify credentials were imported
	for _, expectedCred := range genesisState.Credentials {
		cred, found := f.keeper.Credentials.Get(f.ctx, expectedCred.Id)
		require.NoError(t, found)
		require.Equal(t, expectedCred.Id, cred.Id)
		require.Equal(t, expectedCred.Issuer, cred.Issuer)
	}

	// Verify revoked credentials were imported
	for _, revokedId := range genesisState.RevokedCredentialIds {
		revoked, found := f.keeper.RevokedCredentials.Get(f.ctx, revokedId)
		require.NoError(t, found)
		require.True(t, revoked)
	}

	// Verify device keys were imported
	for _, expectedDk := range genesisState.DeviceKeys {
		dk, found := f.keeper.DeviceKeys.Get(f.ctx, expectedDk.DeviceId)
		require.NoError(t, found)
		require.Equal(t, expectedDk.DeviceId, dk.DeviceId)
		require.Equal(t, expectedDk.Owner, dk.Owner)
		require.Equal(t, expectedDk.Location, dk.Location)
	}

	// Test ExportGenesis
	exported, err := f.keeper.ExportGenesis(f.ctx)
	require.NoError(t, err)
	require.NotNil(t, exported)

	// Verify exported params
	require.EqualExportedValues(t, genesisState.Params, exported.Params)

	// Verify exported DID documents
	require.Len(t, exported.DidDocuments, len(genesisState.DidDocuments))
	for i, doc := range exported.DidDocuments {
		require.Equal(t, genesisState.DidDocuments[i].Id, doc.Id)
		require.Equal(t, genesisState.DidDocuments[i].Controller, doc.Controller)
	}

	// Verify exported credentials
	require.Len(t, exported.Credentials, len(genesisState.Credentials))
	for i, cred := range exported.Credentials {
		require.Equal(t, genesisState.Credentials[i].Id, cred.Id)
		require.Equal(t, genesisState.Credentials[i].Issuer, cred.Issuer)
	}

	// Verify exported revoked credentials
	require.ElementsMatch(t, genesisState.RevokedCredentialIds, exported.RevokedCredentialIds)

	// Verify exported device keys
	require.Len(t, exported.DeviceKeys, len(genesisState.DeviceKeys))
	for i, dk := range exported.DeviceKeys {
		require.Equal(t, genesisState.DeviceKeys[i].DeviceId, dk.DeviceId)
		require.Equal(t, genesisState.DeviceKeys[i].Owner, dk.Owner)
	}
}

func TestGenesisValidation(t *testing.T) {
	tests := []struct {
		name        string
		genesis     types.GenesisState
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid genesis",
			genesis: types.GenesisState{
				Params:               types.DefaultParams(),
				DidDocuments:         []types.DIDDocument{{Id: "did:acmain:test"}},
				Credentials:          []types.VerifiableCredential{{Id: "cred1"}},
				RevokedCredentialIds: []string{"cred2"},
				DeviceKeys:           []types.DeviceKey{{DeviceId: "device1"}},
			},
			expectError: false,
		},
		{
			name: "duplicate DID",
			genesis: types.GenesisState{
				Params: types.DefaultParams(),
				DidDocuments: []types.DIDDocument{
					{Id: "did:acmain:test"},
					{Id: "did:acmain:test"},
				},
			},
			expectError: true,
			errorMsg:    "duplicate DID",
		},
		{
			name: "empty DID ID",
			genesis: types.GenesisState{
				Params:       types.DefaultParams(),
				DidDocuments: []types.DIDDocument{{Id: ""}},
			},
			expectError: true,
			errorMsg:    "DID document has empty ID",
		},
		{
			name: "duplicate credential",
			genesis: types.GenesisState{
				Params: types.DefaultParams(),
				Credentials: []types.VerifiableCredential{
					{Id: "cred1"},
					{Id: "cred1"},
				},
			},
			expectError: true,
			errorMsg:    "duplicate credential ID",
		},
		{
			name: "empty credential ID",
			genesis: types.GenesisState{
				Params:      types.DefaultParams(),
				Credentials: []types.VerifiableCredential{{Id: ""}},
			},
			expectError: true,
			errorMsg:    "credential has empty ID",
		},
		{
			name: "empty revoked credential ID",
			genesis: types.GenesisState{
				Params:               types.DefaultParams(),
				RevokedCredentialIds: []string{""},
			},
			expectError: true,
			errorMsg:    "revoked credential ID cannot be empty",
		},
		{
			name: "duplicate device key",
			genesis: types.GenesisState{
				Params: types.DefaultParams(),
				DeviceKeys: []types.DeviceKey{
					{DeviceId: "device1"},
					{DeviceId: "device1"},
				},
			},
			expectError: true,
			errorMsg:    "duplicate device ID",
		},
		{
			name: "empty device ID",
			genesis: types.GenesisState{
				Params:     types.DefaultParams(),
				DeviceKeys: []types.DeviceKey{{DeviceId: ""}},
			},
			expectError: true,
			errorMsg:    "device key has empty device ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.genesis.Validate()
			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
