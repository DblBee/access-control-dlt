package keeper

import (
	"context"
	"errors"
	"strconv"

	"cosmossdk.io/collections"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"acmain/x/assetmgmt/types"
)

func (q queryServer) AssetsByType(ctx context.Context, req *types.QueryAssetsByTypeRequest) (*types.QueryAssetsByTypeResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	if req.AssetType == "" {
		return nil, status.Error(codes.InvalidArgument, "asset type cannot be empty")
	}

	// Parse asset type string to enum value
	assetTypeInt, err := strconv.ParseInt(req.AssetType, 10, 32)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid asset type: %s", req.AssetType)
	}
	assetType := int32(assetTypeInt)

	var assets []types.Asset

	// Walk through the type index
	// Index structure: (asset_type, asset_id)
	err = q.k.AssetsByType.Walk(ctx, collections.NewPrefixedPairRange[int32, string](assetType), func(key collections.Pair[int32, string]) (stop bool, err error) {
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

	return &types.QueryAssetsByTypeResponse{
		Assets: assets,
	}, nil
}
