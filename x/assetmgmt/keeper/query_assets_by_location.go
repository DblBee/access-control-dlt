package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"acmain/x/assetmgmt/types"
)

func (q queryServer) AssetsByLocation(ctx context.Context, req *types.QueryAssetsByLocationRequest) (*types.QueryAssetsByLocationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	if req.BuildingId == "" {
		return nil, status.Error(codes.InvalidArgument, "building ID cannot be empty")
	}

	var assets []types.Asset

	// Walk through the location index
	// Index structure: (building_id, floor_id, (zone_id, asset_id))
	err := q.k.AssetsByLocation.Walk(ctx, collections.NewPrefixedTripleRange[string, string, collections.Pair[string, string]](req.BuildingId), func(key collections.Triple[string, string, collections.Pair[string, string]]) (stop bool, err error) {
		_, k2, k3 := key.K1(), key.K2(), key.K3()

		// Filter by floor_id if provided
		if req.FloorId != "" && k2 != req.FloorId {
			return false, nil
		}

		// Filter by zone_id if provided
		zoneID, assetID := k3.K1(), k3.K2()
		if req.ZoneId != "" && zoneID != req.ZoneId {
			return false, nil
		}

		// Get the asset
		asset, err := q.k.Assets.Get(ctx, assetID)
		if err != nil {
			// Skip if asset not found (inconsistency)
			if errors.Is(err, collections.ErrNotFound) {
				return false, nil
			}
			return true, err
		}

		assets = append(assets, asset)
		return false, nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAssetsByLocationResponse{
		Assets: assets,
	}, nil
}
