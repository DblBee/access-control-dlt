package types

import "cosmossdk.io/collections"

const (
	// ModuleName defines the module name
	ModuleName = "assetmgmt"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// GovModuleName duplicates the gov module's name to avoid a dependency with x/gov.
	// It should be synced with the gov module's name if it is ever changed.
	// See: https://github.com/cosmos/cosmos-sdk/blob/v0.52.0-beta.2/x/gov/types/keys.go#L9
	GovModuleName = "gov"
)

// Storage prefixes for collections
var (
	// ParamsKey is the prefix to retrieve all Params
	ParamsKey = collections.NewPrefix(0)

	// AssetsPrefix is the prefix for the primary asset storage
	AssetsPrefix = collections.NewPrefix(1)

	// AssetsByLocationPrefix is the prefix for the location index
	AssetsByLocationPrefix = collections.NewPrefix(2)

	// AssetsByControllerPrefix is the prefix for the controller index
	AssetsByControllerPrefix = collections.NewPrefix(3)

	// AssetsByTypePrefix is the prefix for the type index
	AssetsByTypePrefix = collections.NewPrefix(4)

	// AssetsByStatePrefix is the prefix for the state index
	AssetsByStatePrefix = collections.NewPrefix(5)
)
