package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"acmain/x/assetmgmt/types"
)

func (q queryServer) AssetsByController(ctx context.Context, req *types.QueryAssetsByControllerRequest) (*types.QueryAssetsByControllerResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	if req.ControllerAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "controller address cannot be empty")
	}

	// Validate controller address
	_, err := q.k.addressCodec.StringToBytes(req.ControllerAddress)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid controller address: %s", err.Error())
	}

	var assets []types.Asset

	// Walk through the controller index
	// Index structure: (controller_address, asset_id)
	err = q.k.AssetsByController.Walk(ctx, collections.NewPrefixedPairRange[string, string](req.ControllerAddress), func(key collections.Pair[string, string]) (stop bool, err error) {
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

	return &types.QueryAssetsByControllerResponse{
		Assets: assets,
	}, nil
}
