package types

// DONTCOVER

import (
	"cosmossdk.io/errors"
)

// x/assetmgmt module sentinel errors
var (
	ErrInvalidSigner      = errors.Register(ModuleName, 1100, "expected gov account as only signer for proposal message")
	ErrInvalidAsset       = errors.Register(ModuleName, 1101, "invalid asset")
	ErrAssetNotFound      = errors.Register(ModuleName, 1102, "asset not found")
	ErrUnauthorized       = errors.Register(ModuleName, 1103, "unauthorized")
	ErrAssetAlreadyExists = errors.Register(ModuleName, 1104, "asset already exists")
)
