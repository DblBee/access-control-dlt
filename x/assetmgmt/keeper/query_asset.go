package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"acmain/x/assetmgmt/types"
)

func (q queryServer) Asset(ctx context.Context, req *types.QueryAssetRequest) (*types.QueryAssetResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	if req.AssetId == "" {
		return nil, status.Error(codes.InvalidArgument, "asset ID cannot be empty")
	}

	// Get asset from storage
	asset, err := q.k.Assets.Get(ctx, req.AssetId)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "asset with ID %s not found", req.AssetId)
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAssetResponse{Asset: asset}, nil
}
