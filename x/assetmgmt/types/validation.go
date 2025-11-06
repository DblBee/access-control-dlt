package types

import (
	"regexp"
	"strings"

	sdkerrors "cosmossdk.io/errors"
)

const (
	// MaxAssetIDLength is the maximum length for an asset ID
	MaxAssetIDLength = 128

	// MaxAssetNameLength is the maximum length for an asset name
	MaxAssetNameLength = 256

	// MaxAssetDescriptionLength is the maximum length for an asset description
	MaxAssetDescriptionLength = 1024

	// MaxLocationIDLength is the maximum length for location IDs
	MaxLocationIDLength = 128

	// MaxMetadataEntries is the maximum number of metadata entries
	MaxMetadataEntries = 50

	// MaxMetadataKeyLength is the maximum length for a metadata key
	MaxMetadataKeyLength = 64

	// MaxMetadataValueLength is the maximum length for a metadata value
	MaxMetadataValueLength = 256
)

var (
	// assetIDRegex validates asset IDs (alphanumeric, hyphens, underscores)
	assetIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	// locationIDRegex validates location IDs (alphanumeric, hyphens, underscores)
	locationIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	// metadataKeyRegex validates metadata keys (alphanumeric, hyphens, underscores)
	metadataKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// ValidateAssetID validates an asset ID
func ValidateAssetID(assetID string) error {
	if assetID == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "asset ID cannot be empty")
	}

	if len(assetID) > MaxAssetIDLength {
		return sdkerrors.Wrapf(ErrInvalidAsset, "asset ID exceeds maximum length of %d", MaxAssetIDLength)
	}

	if !assetIDRegex.MatchString(assetID) {
		return sdkerrors.Wrap(ErrInvalidAsset, "asset ID can only contain alphanumeric characters, hyphens, and underscores")
	}

	return nil
}

// ValidateAssetName validates an asset name
func ValidateAssetName(name string) error {
	if name == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "asset name cannot be empty")
	}

	if len(name) > MaxAssetNameLength {
		return sdkerrors.Wrapf(ErrInvalidAsset, "asset name exceeds maximum length of %d", MaxAssetNameLength)
	}

	return nil
}

// ValidateAssetDescription validates an asset description
func ValidateAssetDescription(description string) error {
	if len(description) > MaxAssetDescriptionLength {
		return sdkerrors.Wrapf(ErrInvalidAsset, "asset description exceeds maximum length of %d", MaxAssetDescriptionLength)
	}

	return nil
}

// ValidateAssetType validates an asset type
func ValidateAssetType(assetType AssetType) error {
	if assetType == ASSET_TYPE_UNSPECIFIED {
		return sdkerrors.Wrap(ErrInvalidAsset, "asset type cannot be unspecified")
	}

	// Check if it's a valid enum value
	if _, ok := AssetType_name[int32(assetType)]; !ok {
		return sdkerrors.Wrap(ErrInvalidAsset, "invalid asset type")
	}

	return nil
}

// ValidateAssetState validates an asset state
func ValidateAssetState(state AssetState) error {
	// ASSET_STATE_UNSPECIFIED is allowed as a query filter but not for setting
	// Check if it's a valid enum value
	if _, ok := AssetState_name[int32(state)]; !ok {
		return sdkerrors.Wrap(ErrInvalidAsset, "invalid asset state")
	}

	return nil
}

// ValidateLocationInfo validates location information
func ValidateLocationInfo(location *LocationInfo) error {
	if location == nil {
		return sdkerrors.Wrap(ErrInvalidAsset, "location cannot be nil")
	}

	if location.BuildingId == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "building ID cannot be empty")
	}

	if len(location.BuildingId) > MaxLocationIDLength {
		return sdkerrors.Wrapf(ErrInvalidAsset, "building ID exceeds maximum length of %d", MaxLocationIDLength)
	}

	if !locationIDRegex.MatchString(location.BuildingId) {
		return sdkerrors.Wrap(ErrInvalidAsset, "building ID can only contain alphanumeric characters, hyphens, and underscores")
	}

	if location.FloorId != "" {
		if len(location.FloorId) > MaxLocationIDLength {
			return sdkerrors.Wrapf(ErrInvalidAsset, "floor ID exceeds maximum length of %d", MaxLocationIDLength)
		}

		if !locationIDRegex.MatchString(location.FloorId) {
			return sdkerrors.Wrap(ErrInvalidAsset, "floor ID can only contain alphanumeric characters, hyphens, and underscores")
		}
	}

	if location.ZoneId != "" {
		if len(location.ZoneId) > MaxLocationIDLength {
			return sdkerrors.Wrapf(ErrInvalidAsset, "zone ID exceeds maximum length of %d", MaxLocationIDLength)
		}

		if !locationIDRegex.MatchString(location.ZoneId) {
			return sdkerrors.Wrap(ErrInvalidAsset, "zone ID can only contain alphanumeric characters, hyphens, and underscores")
		}
	}

	// Validate latitude
	if location.LatitudeMicrodegrees < -90000000 || location.LatitudeMicrodegrees > 90000000 {
		return sdkerrors.Wrap(ErrInvalidAsset, "latitude must be between -90 and 90 degrees")
	}

	// Validate longitude
	if location.LongitudeMicrodegrees < -180000000 || location.LongitudeMicrodegrees > 180000000 {
		return sdkerrors.Wrap(ErrInvalidAsset, "longitude must be between -180 and 180 degrees")
	}

	return nil
}

// ValidateMetadata validates asset metadata
func ValidateMetadata(metadata map[string]string) error {
	if len(metadata) > MaxMetadataEntries {
		return sdkerrors.Wrapf(ErrInvalidAsset, "metadata exceeds maximum of %d entries", MaxMetadataEntries)
	}

	for key, value := range metadata {
		if key == "" {
			return sdkerrors.Wrap(ErrInvalidAsset, "metadata key cannot be empty")
		}

		if len(key) > MaxMetadataKeyLength {
			return sdkerrors.Wrapf(ErrInvalidAsset, "metadata key '%s' exceeds maximum length of %d", key, MaxMetadataKeyLength)
		}

		if !metadataKeyRegex.MatchString(key) {
			return sdkerrors.Wrapf(ErrInvalidAsset, "metadata key '%s' can only contain alphanumeric characters, hyphens, and underscores", key)
		}

		if len(value) > MaxMetadataValueLength {
			return sdkerrors.Wrapf(ErrInvalidAsset, "metadata value for key '%s' exceeds maximum length of %d", key, MaxMetadataValueLength)
		}

		// Check for reserved keys
		if strings.HasPrefix(key, "_") {
			return sdkerrors.Wrapf(ErrInvalidAsset, "metadata key '%s' is reserved (cannot start with underscore)", key)
		}
	}

	return nil
}

// ValidateAsset validates all fields of an asset
func ValidateAsset(asset *Asset) error {
	if asset == nil {
		return sdkerrors.Wrap(ErrInvalidAsset, "asset cannot be nil")
	}

	if err := ValidateAssetID(asset.AssetId); err != nil {
		return err
	}

	if err := ValidateAssetType(asset.AssetType); err != nil {
		return err
	}

	if err := ValidateAssetName(asset.Name); err != nil {
		return err
	}

	if err := ValidateAssetDescription(asset.Description); err != nil {
		return err
	}

	if err := ValidateLocationInfo(&asset.Location); err != nil {
		return err
	}

	if asset.ControllerAddress == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "controller address cannot be empty")
	}

	if err := ValidateAssetState(asset.State); err != nil {
		return err
	}

	if err := ValidateMetadata(asset.Metadata); err != nil {
		return err
	}

	return nil
}

// Validate validates MsgCreateAsset
func (msg *MsgCreateAsset) Validate() error {
	if msg.Creator == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "creator address cannot be empty")
	}

	if err := ValidateAssetID(msg.AssetId); err != nil {
		return err
	}

	if err := ValidateAssetType(msg.AssetType); err != nil {
		return err
	}

	if err := ValidateAssetName(msg.Name); err != nil {
		return err
	}

	if err := ValidateAssetDescription(msg.Description); err != nil {
		return err
	}

	if err := ValidateLocationInfo(&msg.Location); err != nil {
		return err
	}

	if msg.ControllerAddress == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "controller address cannot be empty")
	}

	if err := ValidateMetadata(msg.Metadata); err != nil {
		return err
	}

	return nil
}

// Validate validates MsgUpdateAssetState
func (msg *MsgUpdateAssetState) Validate() error {
	if msg.Controller == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "controller address cannot be empty")
	}

	if err := ValidateAssetID(msg.AssetId); err != nil {
		return err
	}

	if msg.NewState == ASSET_STATE_UNSPECIFIED {
		return sdkerrors.Wrap(ErrInvalidAsset, "new state cannot be unspecified")
	}

	if err := ValidateAssetState(msg.NewState); err != nil {
		return err
	}

	return nil
}

// Validate validates MsgUpdateAssetMetadata
func (msg *MsgUpdateAssetMetadata) Validate() error {
	if msg.Controller == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "controller address cannot be empty")
	}

	if err := ValidateAssetID(msg.AssetId); err != nil {
		return err
	}

	if err := ValidateMetadata(msg.Metadata); err != nil {
		return err
	}

	return nil
}

// Validate validates MsgTransferAssetController
func (msg *MsgTransferAssetController) Validate() error {
	if msg.CurrentController == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "current controller address cannot be empty")
	}

	if err := ValidateAssetID(msg.AssetId); err != nil {
		return err
	}

	if msg.NewController == "" {
		return sdkerrors.Wrap(ErrInvalidAsset, "new controller address cannot be empty")
	}

	if msg.CurrentController == msg.NewController {
		return sdkerrors.Wrap(ErrInvalidAsset, "new controller cannot be the same as current controller")
	}

	return nil
}
