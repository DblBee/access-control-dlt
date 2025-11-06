package keeper

import (
	"context"

	"cosmossdk.io/collections"
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"acmain/x/assetmgmt/types"
)

func (k msgServer) TransferAssetController(ctx context.Context, msg *types.MsgTransferAssetController) (*types.MsgTransferAssetControllerResponse, error) {
	// Validate message
	if err := msg.Validate(); err != nil {
		return nil, err
	}

	// Validate current controller address
	_, err := k.addressCodec.StringToBytes(msg.CurrentController)
	if err != nil {
		return nil, errorsmod.Wrap(err, "invalid current controller address")
	}

	// Validate new controller address
	_, err = k.addressCodec.StringToBytes(msg.NewController)
	if err != nil {
		return nil, errorsmod.Wrap(err, "invalid new controller address")
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
	if asset.ControllerAddress != msg.CurrentController {
		return nil, errorsmod.Wrapf(types.ErrUnauthorized, "only current controller %s can transfer asset control, got %s", asset.ControllerAddress, msg.CurrentController)
	}

	// Remove old controller index entry
	oldControllerKey := collections.Join(msg.CurrentController, msg.AssetId)
	if err := k.AssetsByController.Remove(ctx, oldControllerKey); err != nil {
		return nil, errorsmod.Wrap(err, "failed to remove old controller index")
	}

	// Update asset controller
	asset.ControllerAddress = msg.NewController

	// Update timestamp
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	asset.UpdatedAt = sdkCtx.BlockTime()

	// Save updated asset
	if err := k.Assets.Set(ctx, msg.AssetId, asset); err != nil {
		return nil, errorsmod.Wrap(err, "failed to update asset")
	}

	// Add new controller index entry
	newControllerKey := collections.Join(msg.NewController, msg.AssetId)
	if err := k.AssetsByController.Set(ctx, newControllerKey); err != nil {
		return nil, errorsmod.Wrap(err, "failed to set new controller index")
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"asset_controller_transferred",
			sdk.NewAttribute("asset_id", msg.AssetId),
			sdk.NewAttribute("old_controller", msg.CurrentController),
			sdk.NewAttribute("new_controller", msg.NewController),
		),
	)

	return &types.MsgTransferAssetControllerResponse{}, nil
}
