package keeper

import (
	"context"

	"cosmossdk.io/collections"
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"acmain/x/assetmgmt/types"
)

func (k msgServer) CreateAsset(ctx context.Context, msg *types.MsgCreateAsset) (*types.MsgCreateAssetResponse, error) {
	// Validate message
	if err := msg.Validate(); err != nil {
		return nil, err
	}

	// Validate creator address
	_, err := k.addressCodec.StringToBytes(msg.Creator)
	if err != nil {
		return nil, errorsmod.Wrap(err, "invalid creator address")
	}

	// Validate controller address
	_, err = k.addressCodec.StringToBytes(msg.ControllerAddress)
	if err != nil {
		return nil, errorsmod.Wrap(err, "invalid controller address")
	}

	// Check if asset already exists
	exists, err := k.Assets.Has(ctx, msg.AssetId)
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to check asset existence")
	}
	if exists {
		return nil, errorsmod.Wrapf(types.ErrAssetAlreadyExists, "asset with ID %s already exists", msg.AssetId)
	}

	// Get block time from SDK context
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	blockTime := sdkCtx.BlockTime()

	// Create asset
	asset := types.Asset{
		AssetId:           msg.AssetId,
		AssetType:         msg.AssetType,
		Name:              msg.Name,
		Description:       msg.Description,
		Location:          msg.Location,
		ControllerAddress: msg.ControllerAddress,
		State:             types.ASSET_STATE_OFFLINE, // Default initial state
		Metadata:          msg.Metadata,
		CreatedAt:         blockTime,
		UpdatedAt:         blockTime,
	}

	// Store asset
	if err := k.Assets.Set(ctx, msg.AssetId, asset); err != nil {
		return nil, errorsmod.Wrap(err, "failed to store asset")
	}

	// Build location index: (building_id, floor_id, (zone_id, asset_id))
	locationKey := collections.Join3(
		msg.Location.BuildingId,
		msg.Location.FloorId,
		collections.Join(msg.Location.ZoneId, msg.AssetId),
	)
	if err := k.AssetsByLocation.Set(ctx, locationKey); err != nil {
		return nil, errorsmod.Wrap(err, "failed to set location index")
	}

	// Build controller index: (controller_address, asset_id)
	controllerKey := collections.Join(msg.ControllerAddress, msg.AssetId)
	if err := k.AssetsByController.Set(ctx, controllerKey); err != nil {
		return nil, errorsmod.Wrap(err, "failed to set controller index")
	}

	// Build type index: (asset_type, asset_id)
	typeKey := collections.Join(int32(msg.AssetType), msg.AssetId)
	if err := k.AssetsByType.Set(ctx, typeKey); err != nil {
		return nil, errorsmod.Wrap(err, "failed to set type index")
	}

	// Build state index: (state, asset_id)
	stateKey := collections.Join(int32(asset.State), msg.AssetId)
	if err := k.AssetsByState.Set(ctx, stateKey); err != nil {
		return nil, errorsmod.Wrap(err, "failed to set state index")
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"asset_created",
			sdk.NewAttribute("asset_id", msg.AssetId),
			sdk.NewAttribute("asset_type", msg.AssetType.String()),
			sdk.NewAttribute("controller", msg.ControllerAddress),
			sdk.NewAttribute("building_id", msg.Location.BuildingId),
		),
	)

	return &types.MsgCreateAssetResponse{Asset: asset}, nil
}
