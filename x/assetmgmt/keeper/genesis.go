package keeper

import (
	"context"

	"cosmossdk.io/collections"

	"acmain/x/assetmgmt/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func (k Keeper) InitGenesis(ctx context.Context, genState types.GenesisState) error {
	// Set params
	if err := k.Params.Set(ctx, genState.Params); err != nil {
		return err
	}

	// Import assets and rebuild indices
	for _, asset := range genState.Assets {
		if err := k.Assets.Set(ctx, asset.AssetId, asset); err != nil {
			return err
		}

		// Rebuild controller index
		controllerKey := collections.Join(asset.ControllerAddress, asset.AssetId)
		if err := k.AssetsByController.Set(ctx, controllerKey); err != nil {
			return err
		}

		// Rebuild location index
		locationKey := collections.Join3(
			asset.Location.BuildingId,
			asset.Location.FloorId,
			collections.Join(asset.Location.ZoneId, asset.AssetId),
		)
		if err := k.AssetsByLocation.Set(ctx, locationKey); err != nil {
			return err
		}

		// Rebuild type index
		typeKey := collections.Join(int32(asset.AssetType), asset.AssetId)
		if err := k.AssetsByType.Set(ctx, typeKey); err != nil {
			return err
		}

		// Rebuild state index
		stateKey := collections.Join(int32(asset.State), asset.AssetId)
		if err := k.AssetsByState.Set(ctx, stateKey); err != nil {
			return err
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

	// Export assets
	err = k.Assets.Walk(ctx, nil, func(id string, asset types.Asset) (bool, error) {
		genesis.Assets = append(genesis.Assets, asset)
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	return genesis, nil
}
