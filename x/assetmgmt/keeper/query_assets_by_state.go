package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"acmain/x/assetmgmt/types"
)

func (q queryServer) AssetsByState(ctx context.Context, req *types.QueryAssetsByStateRequest) (*types.QueryAssetsByStateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	// Validate state
	if err := types.ValidateAssetState(req.State); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid asset state: %s", err.Error())
	}

	var assets []types.Asset

	// Walk through the state index
	// Index structure: (asset_state, asset_id)
	err := q.k.AssetsByState.Walk(ctx, collections.NewPrefixedPairRange[int32, string](int32(req.State)), func(key collections.Pair[int32, string]) (stop bool, err error) {
		assetID := key.K2()

		// Get the asset
		asset, err := q.k.Assets.Get(ctx, assetID)
		if err != nil {
			// Skip if asset not found (inconsistency)
			if errors.Is(err, collections.ErrNotFound) {
				return false, nil
			}
			return true, err
		}

		// Filter by building_id if provided
		if req.BuildingId != "" && asset.Location.BuildingId != req.BuildingId {
			return false, nil
		}

		assets = append(assets, asset)
		return false, nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAssetsByStateResponse{
		Assets: assets,
	}, nil
}
