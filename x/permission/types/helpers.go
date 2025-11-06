package types

import (
	"encoding/json"
	"fmt"
	"time"
)

// PermissionBuilder helps construct Permission objects with a fluent API
type PermissionBuilder struct {
	permission Permission
}

// NewPermissionBuilder creates a new permission builder
func NewPermissionBuilder(did, resourceType, resourceID string) *PermissionBuilder {
	return &PermissionBuilder{
		permission: Permission{
			Did:          did,
			ResourceType: resourceType,
			ResourceId:   resourceID,
			GrantedAt:    time.Now(),
			Metadata:     make(map[string]string),
		},
	}
}

// WithPermissions sets the permission bits
func (pb *PermissionBuilder) WithPermissions(permissionBits uint64) *PermissionBuilder {
	pb.permission.PermissionBits = permissionBits
	return pb
}

// AddPermissions adds permission bits to existing permissions
func (pb *PermissionBuilder) AddPermissions(permissionBits uint64) *PermissionBuilder {
	pb.permission.PermissionBits = AddPermission(pb.permission.PermissionBits, permissionBits)
	return pb
}

// WithGrantedBy sets who granted the permission
func (pb *PermissionBuilder) WithGrantedBy(grantedBy string) *PermissionBuilder {
	pb.permission.GrantedBy = grantedBy
	return pb
}

// WithExpiration sets when the permission expires
func (pb *PermissionBuilder) WithExpiration(expiresAt time.Time) *PermissionBuilder {
	pb.permission.ExpiresAt = &expiresAt
	return pb
}

// WithCondition adds a condition to the permission
func (pb *PermissionBuilder) WithCondition(conditionType ConditionType, conditionData string) *PermissionBuilder {
	pb.permission.Conditions = append(pb.permission.Conditions, &PermissionCondition{
		Type:          conditionType,
		ConditionData: conditionData,
	})
	return pb
}

// WithTimeWindow adds a time window condition
func (pb *PermissionBuilder) WithTimeWindow(startTime, endTime time.Time) *PermissionBuilder {
	data, _ := json.Marshal(map[string]string{
		"start": startTime.Format(time.RFC3339),
		"end":   endTime.Format(time.RFC3339),
	})
	return pb.WithCondition(ConditionType_CONDITION_TYPE_TIME_WINDOW, string(data))
}

// WithLocation adds a location condition
func (pb *PermissionBuilder) WithLocation(location string) *PermissionBuilder {
	data, _ := json.Marshal(map[string]string{
		"location": location,
	})
	return pb.WithCondition(ConditionType_CONDITION_TYPE_LOCATION, string(data))
}

// WithMetadata adds metadata to the permission
func (pb *PermissionBuilder) WithMetadata(key, value string) *PermissionBuilder {
	pb.permission.Metadata[key] = value
	return pb
}

// Build returns the constructed permission
func (pb *PermissionBuilder) Build() (*Permission, error) {
	if err := pb.permission.Validate(); err != nil {
		return nil, err
	}
	return &pb.permission, nil
}

// RolePermissionBuilder helps construct RolePermission objects
type RolePermissionBuilder struct {
	role RolePermission
}

// NewRolePermissionBuilder creates a new role permission builder
func NewRolePermissionBuilder(roleName, resourceType string) *RolePermissionBuilder {
	return &RolePermissionBuilder{
		role: RolePermission{
			RoleName:     roleName,
			ResourceType: resourceType,
			CreatedAt:    time.Now(),
		},
	}
}

// WithPermissions sets the permission bits for the role
func (rb *RolePermissionBuilder) WithPermissions(permissionBits uint64) *RolePermissionBuilder {
	rb.role.PermissionBits = permissionBits
	return rb
}

// WithDescription sets the role description
func (rb *RolePermissionBuilder) WithDescription(description string) *RolePermissionBuilder {
	rb.role.Description = description
	return rb
}

// WithCreatedBy sets who created the role
func (rb *RolePermissionBuilder) WithCreatedBy(createdBy string) *RolePermissionBuilder {
	rb.role.CreatedBy = createdBy
	return rb
}

// Build returns the constructed role permission
func (rb *RolePermissionBuilder) Build() (*RolePermission, error) {
	if err := rb.role.Validate(); err != nil {
		return nil, err
	}
	return &rb.role, nil
}

// PermissionSet represents a set of permission bits with helper methods
type PermissionSet struct {
	bits uint64
}

// NewPermissionSet creates a new permission set
func NewPermissionSet(bits uint64) *PermissionSet {
	return &PermissionSet{bits: bits}
}

// Add adds permissions to the set
func (ps *PermissionSet) Add(permissions uint64) *PermissionSet {
	ps.bits = AddPermission(ps.bits, permissions)
	return ps
}

// Remove removes permissions from the set
func (ps *PermissionSet) Remove(permissions uint64) *PermissionSet {
	ps.bits = RemovePermission(ps.bits, permissions)
	return ps
}

// Has checks if the set has a specific permission
func (ps *PermissionSet) Has(permission uint64) bool {
	return HasPermission(ps.bits, permission)
}

// HasAny checks if the set has any of the specified permissions
func (ps *PermissionSet) HasAny(permissions uint64) bool {
	return HasAnyPermission(ps.bits, permissions)
}

// HasAll checks if the set has all of the specified permissions
func (ps *PermissionSet) HasAll(permissions uint64) bool {
	return HasAllPermissions(ps.bits, permissions)
}

// Count returns the number of permissions in the set
func (ps *PermissionSet) Count() int {
	return CountPermissions(ps.bits)
}

// Bits returns the raw permission bits
func (ps *PermissionSet) Bits() uint64 {
	return ps.bits
}

// List returns a slice of individual permission bits
func (ps *PermissionSet) List() []uint64 {
	return ListSetPermissions(ps.bits)
}

// String returns a human-readable representation
func (ps *PermissionSet) String() string {
	permissions := ps.List()
	names := make([]string, len(permissions))
	for i, perm := range permissions {
		names[i] = GetPermissionName(perm)
	}
	return fmt.Sprintf("PermissionSet{bits: 0x%X, permissions: %v}", ps.bits, names)
}

// Common role definitions using permission masks

// NewAssetReadOnlyRole creates a read-only asset role
func NewAssetReadOnlyRole(createdBy string) *RolePermission {
	return &RolePermission{
		RoleName:       "asset_reader",
		ResourceType:   ResourceTypeAsset,
		PermissionBits: PermAssetReadOnly,
		Description:    "Read-only access to assets",
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}
}

// NewAssetOperatorRole creates an asset operator role
func NewAssetOperatorRole(createdBy string) *RolePermission {
	return &RolePermission{
		RoleName:       "asset_operator",
		ResourceType:   ResourceTypeAsset,
		PermissionBits: PermAssetOperator,
		Description:    "Operate and monitor assets",
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}
}

// NewAssetManagerRole creates an asset manager role
func NewAssetManagerRole(createdBy string) *RolePermission {
	return &RolePermission{
		RoleName:       "asset_manager",
		ResourceType:   ResourceTypeAsset,
		PermissionBits: PermAssetManager,
		Description:    "Full asset management capabilities",
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}
}

// NewAssetAdminRole creates an asset admin role
func NewAssetAdminRole(createdBy string) *RolePermission {
	return &RolePermission{
		RoleName:       "asset_admin",
		ResourceType:   ResourceTypeAsset,
		PermissionBits: PermAssetAdmin,
		Description:    "Full asset administrative access",
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}
}

// NewCredentialIssuerRole creates a credential issuer role
func NewCredentialIssuerRole(createdBy string) *RolePermission {
	return &RolePermission{
		RoleName:       "credential_issuer",
		ResourceType:   ResourceTypeCredential,
		PermissionBits: PermCredentialIssuer,
		Description:    "Issue and manage verifiable credentials",
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}
}

// NewDIDManagerRole creates a DID manager role
func NewDIDManagerRole(createdBy string) *RolePermission {
	return &RolePermission{
		RoleName:       "did_manager",
		ResourceType:   ResourceTypeDID,
		PermissionBits: PermDIDManager,
		Description:    "Manage DID documents and keys",
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}
}

// NewDeviceAdminRole creates a device admin role
func NewDeviceAdminRole(createdBy string) *RolePermission {
	return &RolePermission{
		RoleName:       "device_admin",
		ResourceType:   ResourceTypeDevice,
		PermissionBits: PermDeviceAdmin,
		Description:    "Full device management capabilities",
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}
}

// NewSystemAdminRole creates a system admin role
func NewSystemAdminRole(createdBy string) *RolePermission {
	return &RolePermission{
		RoleName:       "system_admin",
		ResourceType:   ResourceTypeSystem,
		PermissionBits: PermAdminAll,
		Description:    "Full system administrative access",
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}
}

// PermissionMatrix is a helper for managing permissions across multiple resources
type PermissionMatrix struct {
	permissions map[string]*PermissionSet // resourceType:resourceID -> PermissionSet
}

// NewPermissionMatrix creates a new permission matrix
func NewPermissionMatrix() *PermissionMatrix {
	return &PermissionMatrix{
		permissions: make(map[string]*PermissionSet),
	}
}

// SetPermissions sets permissions for a resource
func (pm *PermissionMatrix) SetPermissions(resourceType, resourceID string, permissions uint64) {
	key := fmt.Sprintf("%s:%s", resourceType, resourceID)
	pm.permissions[key] = NewPermissionSet(permissions)
}

// GetPermissions gets permissions for a resource
func (pm *PermissionMatrix) GetPermissions(resourceType, resourceID string) *PermissionSet {
	key := fmt.Sprintf("%s:%s", resourceType, resourceID)
	if ps, ok := pm.permissions[key]; ok {
		return ps
	}
	return NewPermissionSet(0)
}

// AddPermissions adds permissions to a resource
func (pm *PermissionMatrix) AddPermissions(resourceType, resourceID string, permissions uint64) {
	ps := pm.GetPermissions(resourceType, resourceID)
	ps.Add(permissions)
	pm.SetPermissions(resourceType, resourceID, ps.Bits())
}

// RemovePermissions removes permissions from a resource
func (pm *PermissionMatrix) RemovePermissions(resourceType, resourceID string, permissions uint64) {
	ps := pm.GetPermissions(resourceType, resourceID)
	ps.Remove(permissions)
	pm.SetPermissions(resourceType, resourceID, ps.Bits())
}

// HasPermission checks if a resource has a specific permission
func (pm *PermissionMatrix) HasPermission(resourceType, resourceID string, permission uint64) bool {
	return pm.GetPermissions(resourceType, resourceID).Has(permission)
}

// GetAllResources returns all resources in the matrix
func (pm *PermissionMatrix) GetAllResources() []string {
	keys := make([]string, 0, len(pm.permissions))
	for k := range pm.permissions {
		keys = append(keys, k)
	}
	return keys
}

// Clear clears all permissions in the matrix
func (pm *PermissionMatrix) Clear() {
	pm.permissions = make(map[string]*PermissionSet)
}

// PermissionMaskHelper provides utility functions for common permission operations
type PermissionMaskHelper struct{}

// NewPermissionMaskHelper creates a new permission mask helper
func NewPermissionMaskHelper() *PermissionMaskHelper {
	return &PermissionMaskHelper{}
}

// GetReadPermissions returns read permissions for a resource type
func (pmh *PermissionMaskHelper) GetReadPermissions(resourceType string) uint64 {
	switch resourceType {
	case ResourceTypeAsset:
		return PermAssetReadOnly
	case ResourceTypeDID:
		return PermDIDReadOnly
	case ResourceTypeCredential:
		return PermCredentialReadOnly
	case ResourceTypeDevice:
		return PermDeviceReadOnly
	default:
		return PermNone
	}
}

// GetFullPermissions returns full permissions for a resource type
func (pmh *PermissionMaskHelper) GetFullPermissions(resourceType string) uint64 {
	switch resourceType {
	case ResourceTypeAsset:
		return PermAssetAll
	case ResourceTypeDID:
		return PermDIDAll
	case ResourceTypeCredential:
		return PermCredentialAll
	case ResourceTypeDevice:
		return PermDeviceAll
	case ResourceTypeSystem:
		return PermAdminAll
	default:
		return PermNone
	}
}

// IsAdminPermission checks if a permission is an administrative permission
func (pmh *PermissionMaskHelper) IsAdminPermission(permission uint64) bool {
	return (permission & PermAdminAll) != 0
}

// FormatPermissions returns a human-readable string of permissions
func FormatPermissions(permissionBits uint64) string {
	if permissionBits == 0 {
		return "none"
	}

	permissions := ListSetPermissions(permissionBits)
	if len(permissions) == 0 {
		return "none"
	}

	result := ""
	for i, perm := range permissions {
		if i > 0 {
			result += ", "
		}
		result += GetPermissionName(perm)
	}

	return result
}

// ParsePermissionNames converts permission names to permission bits
func ParsePermissionNames(names []string) (uint64, error) {
	permissionBits := uint64(0)

	nameToPermission := map[string]uint64{
		// Asset permissions
		"asset.read":     PermAssetRead,
		"asset.update":   PermAssetUpdate,
		"asset.delete":   PermAssetDelete,
		"asset.control":  PermAssetControl,
		"asset.grant":    PermAssetGrant,
		"asset.revoke":   PermAssetRevoke,
		"asset.audit":    PermAssetAudit,
		"asset.maintain": PermAssetMaintain,
		"asset.create":   PermAssetCreate,
		"asset.transfer": PermAssetTransfer,
		"asset.config":   PermAssetConfig,
		"asset.monitor":  PermAssetMonitor,

		// DID permissions
		"did.read":            PermDIDRead,
		"did.update":          PermDIDUpdate,
		"did.delete":          PermDIDDelete,
		"did.create":          PermDIDCreate,
		"did.deactivate":      PermDIDDeactivate,
		"did.add_key":         PermDIDAddKey,
		"did.remove_key":      PermDIDRemoveKey,
		"did.add_service":     PermDIDAddService,
		"did.remove_service":  PermDIDRemoveService,
		"did.update_metadata": PermDIDUpdateMetadata,

		// Credential permissions
		"credential.read":    PermCredentialRead,
		"credential.issue":   PermCredentialIssue,
		"credential.revoke":  PermCredentialRevoke,
		"credential.verify":  PermCredentialVerify,
		"credential.update":  PermCredentialUpdate,
		"credential.suspend": PermCredentialSuspend,
		"credential.resume":  PermCredentialResume,
		"credential.audit":   PermCredentialAudit,

		// Device permissions
		"device.read":     PermDeviceRead,
		"device.register": PermDeviceRegister,
		"device.update":   PermDeviceUpdate,
		"device.revoke":   PermDeviceRevoke,
		"device.rotate":   PermDeviceRotate,
		"device.delete":   PermDeviceDelete,

		// Admin permissions
		"admin.full_access":   PermAdminFullAccess,
		"admin.manage_users":  PermAdminManageUsers,
		"admin.manage_roles":  PermAdminManageRoles,
		"admin.manage_policy": PermAdminManagePolicy,
		"admin.view_audit":    PermAdminViewAudit,
		"admin.system_config": PermAdminSystemConfig,
		"admin.emergency_ops": PermAdminEmergencyOps,
	}

	for _, name := range names {
		perm, ok := nameToPermission[name]
		if !ok {
			return 0, fmt.Errorf("unknown permission name: %s", name)
		}
		permissionBits = AddPermission(permissionBits, perm)
	}

	return permissionBits, nil
}
