package keeper

import (
	"fmt"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"

	"acmain/x/assetmgmt/types"
)

type Keeper struct {
	storeService corestore.KVStoreService
	cdc          codec.Codec
	addressCodec address.Codec
	// Address capable of executing a MsgUpdateParams message.
	// Typically, this should be the x/gov module account.
	authority []byte

	Schema collections.Schema
	Params collections.Item[types.Params]

	// Asset storage
	Assets collections.Map[string, types.Asset]

	// Asset indices for efficient querying
	// AssetsByLocation: (building_id, floor_id, zone_id, asset_id) -> nil
	AssetsByLocation collections.KeySet[collections.Triple[string, string, collections.Pair[string, string]]]

	// AssetsByController: (controller_address, asset_id) -> nil
	AssetsByController collections.KeySet[collections.Pair[string, string]]

	// AssetsByType: (asset_type, asset_id) -> nil
	AssetsByType collections.KeySet[collections.Pair[int32, string]]

	// AssetsByState: (asset_state, asset_id) -> nil
	AssetsByState collections.KeySet[collections.Pair[int32, string]]
}

func NewKeeper(
	storeService corestore.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	authority []byte,

) Keeper {
	if _, err := addressCodec.BytesToString(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address %s: %s", authority, err))
	}

	sb := collections.NewSchemaBuilder(storeService)

	k := Keeper{
		storeService: storeService,
		cdc:          cdc,
		addressCodec: addressCodec,
		authority:    authority,

		Params: collections.NewItem(sb, types.ParamsKey, "params", codec.CollValue[types.Params](cdc)),
		Assets: collections.NewMap(sb, types.AssetsPrefix, "assets", collections.StringKey, codec.CollValue[types.Asset](cdc)),
		AssetsByLocation: collections.NewKeySet(
			sb,
			types.AssetsByLocationPrefix,
			"assets_by_location",
			collections.TripleKeyCodec(
				collections.StringKey,
				collections.StringKey,
				collections.PairKeyCodec(collections.StringKey, collections.StringKey),
			),
		),
		AssetsByController: collections.NewKeySet(
			sb,
			types.AssetsByControllerPrefix,
			"assets_by_controller",
			collections.PairKeyCodec(collections.StringKey, collections.StringKey),
		),
		AssetsByType: collections.NewKeySet(
			sb,
			types.AssetsByTypePrefix,
			"assets_by_type",
			collections.PairKeyCodec(collections.Int32Key, collections.StringKey),
		),
		AssetsByState: collections.NewKeySet(
			sb,
			types.AssetsByStatePrefix,
			"assets_by_state",
			collections.PairKeyCodec(collections.Int32Key, collections.StringKey),
		),
	}

	schema, err := sb.Build()
	if err != nil {
		panic(err)
	}
	k.Schema = schema

	return k
}

// GetAuthority returns the module's authority.
func (k Keeper) GetAuthority() []byte {
	return k.authority
}
