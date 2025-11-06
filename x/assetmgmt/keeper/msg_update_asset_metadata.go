package keeper

import (
	"context"

	"cosmossdk.io/collections"
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"acmain/x/assetmgmt/types"
)

func (k msgServer) UpdateAssetMetadata(ctx context.Context, msg *types.MsgUpdateAssetMetadata) (*types.MsgUpdateAssetMetadataResponse, error) {
	// Validate message
	if err := msg.Validate(); err != nil {
		return nil, err
	}

	// Validate controller address
	_, err := k.addressCodec.StringToBytes(msg.Controller)
	if err != nil {
		return nil, errorsmod.Wrap(err, "invalid controller address")
	}

	// Get asset
	asset, err := k.Assets.Get(ctx, msg.AssetId)
	if err != nil {
		if errorsmod.IsOf(err, collections.ErrNotFound) {
			return nil, errorsmod.Wrapf(types.ErrAssetNotFound, "asset with ID %s not found", msg.AssetId)
		}
		return nil, errorsmod.Wrap(err, "failed to get asset")
	}

	// Verify controller authorization
	if asset.ControllerAddress != msg.Controller {
		return nil, errorsmod.Wrapf(types.ErrUnauthorized, "only controller %s can update asset metadata, got %s", asset.ControllerAddress, msg.Controller)
	}

	// Update metadata (replaces existing)
	asset.Metadata = msg.Metadata

	// Update timestamp
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	asset.UpdatedAt = sdkCtx.BlockTime()

	// Save updated asset
	if err := k.Assets.Set(ctx, msg.AssetId, asset); err != nil {
		return nil, errorsmod.Wrap(err, "failed to update asset")
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"asset_metadata_updated",
			sdk.NewAttribute("asset_id", msg.AssetId),
			sdk.NewAttribute("controller", msg.Controller),
		),
	)

	return &types.MsgUpdateAssetMetadataResponse{}, nil
}
