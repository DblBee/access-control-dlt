package types

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	MaxResourceTypeLength  = 50
	MaxResourceIDLength    = 200
	MaxDIDLength           = 256
	MaxMetadataEntries     = 50
	MaxMetadataKeyLength   = 64
	MaxMetadataValueLength = 256
	MaxConditionDataLength = 1024
	MaxRoleNameLength      = 64
	MaxDescriptionLength   = 500
)

var (
	// DID format: did:method:identifier
	didRegex = regexp.MustCompile(`^did:[a-z0-9]+:[a-zA-Z0-9._-]+$`)

	// Resource type: lowercase alphanumeric and underscore
	resourceTypeRegex = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

	// Role name: alphanumeric, underscore, and hyphen
	roleNameRegex = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
)

// ValidateDID validates a DID string format
func ValidateDID(did string) error {
	if did == "" {
		return fmt.Errorf("DID cannot be empty")
	}

	if len(did) > MaxDIDLength {
		return fmt.Errorf("DID exceeds maximum length of %d characters", MaxDIDLength)
	}

	if !didRegex.MatchString(did) {
		return fmt.Errorf("invalid DID format: %s (expected format: did:method:identifier)", did)
	}

	return nil
}

// ValidateResourceType validates a resource type string
func ValidateResourceType(resourceType string) error {
	if resourceType == "" {
		return fmt.Errorf("resource type cannot be empty")
	}

	if len(resourceType) > MaxResourceTypeLength {
		return fmt.Errorf("resource type exceeds maximum length of %d characters", MaxResourceTypeLength)
	}

	if !resourceTypeRegex.MatchString(resourceType) {
		return fmt.Errorf("invalid resource type format: %s (must start with lowercase letter and contain only lowercase letters, numbers, and underscores)", resourceType)
	}

	return nil
}

// ValidateResourceID validates a resource identifier
func ValidateResourceID(resourceID string) error {
	// Empty resource ID is valid (means "all resources")
	if resourceID == "" {
		return nil
	}

	if len(resourceID) > MaxResourceIDLength {
		return fmt.Errorf("resource ID exceeds maximum length of %d characters", MaxResourceIDLength)
	}

	// Resource ID should not contain control characters
	for _, r := range resourceID {
		if r < 32 || r == 127 {
			return fmt.Errorf("resource ID contains invalid control characters")
		}
	}

	return nil
}

// ValidatePermissionBitsForResourceType validates permission bits for a specific resource type
func ValidatePermissionBitsForResourceType(resourceType string, permissionBits uint64) error {
	if permissionBits == 0 {
		return fmt.Errorf("permission bits cannot be zero")
	}

	if !ValidatePermissionBits(resourceType, permissionBits) {
		return fmt.Errorf("invalid permission bits 0x%X for resource type %s", permissionBits, resourceType)
	}

	return nil
}

// ValidateMetadata validates permission metadata
func ValidateMetadata(metadata map[string]string) error {
	if len(metadata) > MaxMetadataEntries {
		return fmt.Errorf("metadata exceeds maximum of %d entries", MaxMetadataEntries)
	}

	for key, value := range metadata {
		if key == "" {
			return fmt.Errorf("metadata key cannot be empty")
		}

		if len(key) > MaxMetadataKeyLength {
			return fmt.Errorf("metadata key '%s' exceeds maximum length of %d characters", key, MaxMetadataKeyLength)
		}

		if len(value) > MaxMetadataValueLength {
			return fmt.Errorf("metadata value for key '%s' exceeds maximum length of %d characters", key, MaxMetadataValueLength)
		}

		// Keys should not contain control characters or spaces
		if strings.ContainsAny(key, " \t\n\r") {
			return fmt.Errorf("metadata key '%s' cannot contain whitespace", key)
		}
	}

	return nil
}

// ValidateRoleName validates a role name
func ValidateRoleName(roleName string) error {
	if roleName == "" {
		return fmt.Errorf("role name cannot be empty")
	}

	if len(roleName) > MaxRoleNameLength {
		return fmt.Errorf("role name exceeds maximum length of %d characters", MaxRoleNameLength)
	}

	if !roleNameRegex.MatchString(roleName) {
		return fmt.Errorf("invalid role name format: %s (must start with letter and contain only letters, numbers, underscores, and hyphens)", roleName)
	}

	return nil
}

// ValidateDescription validates a description string
func ValidateDescription(description string) error {
	if len(description) > MaxDescriptionLength {
		return fmt.Errorf("description exceeds maximum length of %d characters", MaxDescriptionLength)
	}

	return nil
}

// ValidateConditionData validates permission condition data
func ValidateConditionData(conditionData string) error {
	if len(conditionData) > MaxConditionDataLength {
		return fmt.Errorf("condition data exceeds maximum length of %d characters", MaxConditionDataLength)
	}

	return nil
}

// ValidatePermission validates a Permission message
func (p *Permission) Validate() error {
	// Validate DID
	if err := ValidateDID(p.Did); err != nil {
		return fmt.Errorf("invalid DID: %w", err)
	}

	// Validate resource type
	if err := ValidateResourceType(p.ResourceType); err != nil {
		return fmt.Errorf("invalid resource type: %w", err)
	}

	// Validate resource ID (can be empty)
	if err := ValidateResourceID(p.ResourceId); err != nil {
		return fmt.Errorf("invalid resource ID: %w", err)
	}

	// Validate permission bits
	if err := ValidatePermissionBitsForResourceType(p.ResourceType, p.PermissionBits); err != nil {
		return fmt.Errorf("invalid permission bits: %w", err)
	}

	// Validate granted_by DID
	if err := ValidateDID(p.GrantedBy); err != nil {
		return fmt.Errorf("invalid granted_by DID: %w", err)
	}

	// Validate timestamps
	if p.GrantedAt.IsZero() {
		return fmt.Errorf("granted_at timestamp cannot be zero")
	}

	// If expires_at is set, it must be after granted_at
	if p.ExpiresAt != nil && !p.ExpiresAt.IsZero() && p.ExpiresAt.Before(p.GrantedAt) {
		return fmt.Errorf("expires_at must be after granted_at")
	}

	// Validate revocation
	if p.Revoked {
		if p.RevokedAt == nil || p.RevokedAt.IsZero() {
			return fmt.Errorf("revoked_at must be set when permission is revoked")
		}
		if p.RevokedBy == "" {
			return fmt.Errorf("revoked_by must be set when permission is revoked")
		}
		if err := ValidateDID(p.RevokedBy); err != nil {
			return fmt.Errorf("invalid revoked_by DID: %w", err)
		}
	}

	// Validate conditions
	for i, condition := range p.Conditions {
		if err := condition.Validate(); err != nil {
			return fmt.Errorf("invalid condition at index %d: %w", i, err)
		}
	}

	// Validate metadata
	if err := ValidateMetadata(p.Metadata); err != nil {
		return fmt.Errorf("invalid metadata: %w", err)
	}

	return nil
}

// IsActive checks if a permission is currently active (not revoked and not expired)
func (p *Permission) IsActive() bool {
	if p.Revoked {
		return false
	}

	now := time.Now()
	if p.ExpiresAt != nil && !p.ExpiresAt.IsZero() && now.After(*p.ExpiresAt) {
		return false
	}

	return true
}

// ValidatePermissionCondition validates a PermissionCondition message
func (pc *PermissionCondition) Validate() error {
	if pc.Type == ConditionType_CONDITION_TYPE_UNSPECIFIED {
		return fmt.Errorf("condition type cannot be unspecified")
	}

	if err := ValidateConditionData(pc.ConditionData); err != nil {
		return fmt.Errorf("invalid condition data: %w", err)
	}

	// Condition data should not be empty for most condition types
	if pc.ConditionData == "" && pc.Type != ConditionType_CONDITION_TYPE_MFA {
		return fmt.Errorf("condition data cannot be empty for condition type %s", pc.Type)
	}

	return nil
}

// ValidatePermissionBitDefinition validates a PermissionBitDefinition message
func (pbd *PermissionBitDefinition) Validate() error {
	// Validate resource type
	if err := ValidateResourceType(pbd.ResourceType); err != nil {
		return fmt.Errorf("invalid resource type: %w", err)
	}

	// Validate bit position (0-63)
	if pbd.BitPosition > 63 {
		return fmt.Errorf("bit position must be between 0 and 63, got %d", pbd.BitPosition)
	}

	// Validate name
	if pbd.Name == "" {
		return fmt.Errorf("permission name cannot be empty")
	}

	if len(pbd.Name) > MaxRoleNameLength {
		return fmt.Errorf("permission name exceeds maximum length of %d characters", MaxRoleNameLength)
	}

	// Validate description
	if err := ValidateDescription(pbd.Description); err != nil {
		return fmt.Errorf("invalid description: %w", err)
	}

	// Validate timestamp
	if pbd.CreatedAt.IsZero() {
		return fmt.Errorf("created_at timestamp cannot be zero")
	}

	return nil
}

// ValidateRolePermission validates a RolePermission message
func (rp *RolePermission) Validate() error {
	// Validate role name
	if err := ValidateRoleName(rp.RoleName); err != nil {
		return fmt.Errorf("invalid role name: %w", err)
	}

	// Validate resource type
	if err := ValidateResourceType(rp.ResourceType); err != nil {
		return fmt.Errorf("invalid resource type: %w", err)
	}

	// Validate permission bits
	if err := ValidatePermissionBitsForResourceType(rp.ResourceType, rp.PermissionBits); err != nil {
		return fmt.Errorf("invalid permission bits: %w", err)
	}

	// Validate description
	if err := ValidateDescription(rp.Description); err != nil {
		return fmt.Errorf("invalid description: %w", err)
	}

	// Validate timestamps
	if rp.CreatedAt.IsZero() {
		return fmt.Errorf("created_at timestamp cannot be zero")
	}

	// Validate created_by DID
	if err := ValidateDID(rp.CreatedBy); err != nil {
		return fmt.Errorf("invalid created_by DID: %w", err)
	}

	return nil
}

// ValidateDIDPermissionAssignment validates a DIDPermissionAssignment message
func (dpa *DIDPermissionAssignment) Validate() error {
	// Validate DID
	if err := ValidateDID(dpa.Did); err != nil {
		return fmt.Errorf("invalid DID: %w", err)
	}

	// Validate each permission
	for i, perm := range dpa.Permissions {
		if err := perm.Validate(); err != nil {
			return fmt.Errorf("invalid permission at index %d: %w", i, err)
		}

		// Permission DID must match assignment DID
		if perm.Did != dpa.Did {
			return fmt.Errorf("permission DID at index %d does not match assignment DID", i)
		}
	}

	// Validate role names
	for i, roleName := range dpa.Roles {
		if err := ValidateRoleName(roleName); err != nil {
			return fmt.Errorf("invalid role at index %d: %w", i, err)
		}
	}

	// Validate timestamps
	if dpa.CreatedAt.IsZero() {
		return fmt.Errorf("created_at timestamp cannot be zero")
	}

	return nil
}

// ValidatePermissionAuditLog validates a PermissionAuditLog message
func (pal *PermissionAuditLog) Validate() error {
	// Validate ID
	if pal.Id == "" {
		return fmt.Errorf("audit log ID cannot be empty")
	}

	// Validate action
	if pal.Action == PermissionAction_PERMISSION_ACTION_UNSPECIFIED {
		return fmt.Errorf("permission action cannot be unspecified")
	}

	// Validate DIDs
	if err := ValidateDID(pal.ActorDid); err != nil {
		return fmt.Errorf("invalid actor DID: %w", err)
	}

	if pal.SubjectDid != "" {
		if err := ValidateDID(pal.SubjectDid); err != nil {
			return fmt.Errorf("invalid subject DID: %w", err)
		}
	}

	// Validate resource type
	if err := ValidateResourceType(pal.ResourceType); err != nil {
		return fmt.Errorf("invalid resource type: %w", err)
	}

	// Validate resource ID (can be empty)
	if err := ValidateResourceID(pal.ResourceId); err != nil {
		return fmt.Errorf("invalid resource ID: %w", err)
	}

	// Validate timestamp
	if pal.Timestamp.IsZero() {
		return fmt.Errorf("timestamp cannot be zero")
	}

	// Validate metadata
	if err := ValidateMetadata(pal.Metadata); err != nil {
		return fmt.Errorf("invalid metadata: %w", err)
	}

	return nil
}

// ValidateCosmosAddress validates a Cosmos SDK address
func ValidateCosmosAddress(address string) error {
	if address == "" {
		return fmt.Errorf("address cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(address)
	if err != nil {
		return fmt.Errorf("invalid cosmos address: %w", err)
	}

	return nil
}
