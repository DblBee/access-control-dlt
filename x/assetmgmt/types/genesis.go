package types

import (
	"fmt"
)

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Params: DefaultParams(),
		Assets: []Asset{},
	}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	// Validate params
	if err := gs.Params.Validate(); err != nil {
		return err
	}

	// Validate assets
	assetSet := make(map[string]bool)
	for _, asset := range gs.Assets {
		if asset.AssetId == "" {
			return fmt.Errorf("asset has empty asset ID")
		}
		if assetSet[asset.AssetId] {
			return fmt.Errorf("duplicate asset ID: %s", asset.AssetId)
		}
		assetSet[asset.AssetId] = true

		// Validate controller address is not empty
		if asset.ControllerAddress == "" {
			return fmt.Errorf("asset %s has empty controller address", asset.AssetId)
		}

		// Validate name is not empty
		if asset.Name == "" {
			return fmt.Errorf("asset %s has empty name", asset.AssetId)
		}
	}

	return nil
}
