package keeper

import (
	"context"

	"cosmossdk.io/collections"

	"acmain/x/iam/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func (k Keeper) InitGenesis(ctx context.Context, genState types.GenesisState) error {
	// Set params
	if err := k.Params.Set(ctx, genState.Params); err != nil {
		return err
	}

	// Import DID documents and rebuild indices
	for _, doc := range genState.DidDocuments {
		if err := k.DIDDocuments.Set(ctx, doc.Id, doc); err != nil {
			return err
		}
		// Rebuild controller index
		if err := k.DIDsByController.Set(ctx, collections.Join(doc.Controller, doc.Id)); err != nil {
			return err
		}
	}

	// Import credentials and rebuild indices
	for _, cred := range genState.Credentials {
		if err := k.Credentials.Set(ctx, cred.Id, cred); err != nil {
			return err
		}
		// Rebuild subject index
		if err := k.CredentialsBySubject.Set(ctx, collections.Join(cred.CredentialSubject.Id, cred.Id)); err != nil {
			return err
		}
		// Rebuild issuer index
		if err := k.CredentialsByIssuer.Set(ctx, collections.Join(cred.Issuer, cred.Id)); err != nil {
			return err
		}
	}

	// Import revoked credentials
	for _, id := range genState.RevokedCredentialIds {
		if err := k.RevokedCredentials.Set(ctx, id, true); err != nil {
			return err
		}
	}

	// Import device keys and rebuild indices
	for _, dk := range genState.DeviceKeys {
		if err := k.DeviceKeys.Set(ctx, dk.DeviceId, dk); err != nil {
			return err
		}
		// Rebuild owner index
		if err := k.DeviceKeysByOwner.Set(ctx, collections.Join(dk.Owner, dk.DeviceId)); err != nil {
			return err
		}
		// Rebuild location index (if location is not empty)
		if dk.Location != "" {
			if err := k.DeviceKeysByLocation.Set(ctx, collections.Join(dk.Location, dk.DeviceId)); err != nil {
				return err
			}
		}
	}

	return nil
}

// ExportGenesis returns the module's exported genesis.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	var err error
	genesis := types.DefaultGenesis()

	// Export params
	genesis.Params, err = k.Params.Get(ctx)
	if err != nil {
		return nil, err
	}

	// Export DID documents
	err = k.DIDDocuments.Walk(ctx, nil, func(did string, doc types.DIDDocument) (bool, error) {
		genesis.DidDocuments = append(genesis.DidDocuments, doc)
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	// Export credentials
	err = k.Credentials.Walk(ctx, nil, func(id string, cred types.VerifiableCredential) (bool, error) {
		genesis.Credentials = append(genesis.Credentials, cred)
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	// Export revoked credentials
	err = k.RevokedCredentials.Walk(ctx, nil, func(id string, revoked bool) (bool, error) {
		if revoked {
			genesis.RevokedCredentialIds = append(genesis.RevokedCredentialIds, id)
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	// Export device keys
	err = k.DeviceKeys.Walk(ctx, nil, func(id string, dk types.DeviceKey) (bool, error) {
		genesis.DeviceKeys = append(genesis.DeviceKeys, dk)
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	return genesis, nil
}
