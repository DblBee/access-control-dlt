package keeper

import (
	"context"

	"cosmossdk.io/collections"
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"acmain/x/assetmgmt/types"
)

func (k msgServer) UpdateAssetState(ctx context.Context, msg *types.MsgUpdateAssetState) (*types.MsgUpdateAssetStateResponse, error) {
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
		return nil, errorsmod.Wrapf(types.ErrUnauthorized, "only controller %s can update asset state, got %s", asset.ControllerAddress, msg.Controller)
	}

	// Check if state is actually changing
	if asset.State == msg.NewState {
		return &types.MsgUpdateAssetStateResponse{}, nil
	}

	// Remove old state index entry
	oldStateKey := collections.Join(int32(asset.State), msg.AssetId)
	if err := k.AssetsByState.Remove(ctx, oldStateKey); err != nil {
		return nil, errorsmod.Wrap(err, "failed to remove old state index")
	}

	// Update asset state
	oldState := asset.State
	asset.State = msg.NewState

	// Update timestamp
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	asset.UpdatedAt = sdkCtx.BlockTime()

	// Save updated asset
	if err := k.Assets.Set(ctx, msg.AssetId, asset); err != nil {
		return nil, errorsmod.Wrap(err, "failed to update asset")
	}

	// Add new state index entry
	newStateKey := collections.Join(int32(msg.NewState), msg.AssetId)
	if err := k.AssetsByState.Set(ctx, newStateKey); err != nil {
		return nil, errorsmod.Wrap(err, "failed to set new state index")
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"asset_state_updated",
			sdk.NewAttribute("asset_id", msg.AssetId),
			sdk.NewAttribute("old_state", oldState.String()),
			sdk.NewAttribute("new_state", msg.NewState.String()),
			sdk.NewAttribute("controller", msg.Controller),
		),
	)

	return &types.MsgUpdateAssetStateResponse{}, nil
}
