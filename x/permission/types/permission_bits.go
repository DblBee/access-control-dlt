package types

// Permission bit definitions using bitwise operations
// Each permission is represented by a single bit in a uint64
const (
	// Asset Permissions (bits 0-15)
	PermAssetRead     uint64 = 1 << 0  // 0x0001 - Read asset information
	PermAssetUpdate   uint64 = 1 << 1  // 0x0002 - Update asset properties
	PermAssetDelete   uint64 = 1 << 2  // 0x0004 - Delete asset
	PermAssetControl  uint64 = 1 << 3  // 0x0008 - Control asset (lock/unlock)
	PermAssetGrant    uint64 = 1 << 4  // 0x0010 - Grant access to asset
	PermAssetRevoke   uint64 = 1 << 5  // 0x0020 - Revoke access to asset
	PermAssetAudit    uint64 = 1 << 6  // 0x0040 - View asset audit logs
	PermAssetMaintain uint64 = 1 << 7  // 0x0080 - Perform maintenance operations
	PermAssetCreate   uint64 = 1 << 8  // 0x0100 - Create new assets
	PermAssetTransfer uint64 = 1 << 9  // 0x0200 - Transfer asset ownership
	PermAssetConfig   uint64 = 1 << 10 // 0x0400 - Configure asset settings
	PermAssetMonitor  uint64 = 1 << 11 // 0x0800 - Monitor asset status

	// DID Permissions (bits 16-31)
	PermDIDRead           uint64 = 1 << 16 // 0x010000 - Read DID documents
	PermDIDUpdate         uint64 = 1 << 17 // 0x020000 - Update DID documents
	PermDIDDelete         uint64 = 1 << 18 // 0x040000 - Delete DID documents
	PermDIDCreate         uint64 = 1 << 19 // 0x080000 - Create DID documents
	PermDIDDeactivate     uint64 = 1 << 20 // 0x100000 - Deactivate DID documents
	PermDIDAddKey         uint64 = 1 << 21 // 0x200000 - Add keys to DID
	PermDIDRemoveKey      uint64 = 1 << 22 // 0x400000 - Remove keys from DID
	PermDIDAddService     uint64 = 1 << 23 // 0x800000 - Add service endpoints
	PermDIDRemoveService  uint64 = 1 << 24 // 0x1000000 - Remove service endpoints
	PermDIDUpdateMetadata uint64 = 1 << 25 // 0x2000000 - Update DID metadata

	// Credential Permissions (bits 32-47)
	PermCredentialRead    uint64 = 1 << 32 // 0x100000000 - Read credentials
	PermCredentialIssue   uint64 = 1 << 33 // 0x200000000 - Issue credentials
	PermCredentialRevoke  uint64 = 1 << 34 // 0x400000000 - Revoke credentials
	PermCredentialVerify  uint64 = 1 << 35 // 0x800000000 - Verify credentials
	PermCredentialUpdate  uint64 = 1 << 36 // 0x1000000000 - Update credentials
	PermCredentialSuspend uint64 = 1 << 37 // 0x2000000000 - Suspend credentials
	PermCredentialResume  uint64 = 1 << 38 // 0x4000000000 - Resume credentials
	PermCredentialAudit   uint64 = 1 << 39 // 0x8000000000 - Audit credentials

	// Device Permissions (bits 48-55)
	PermDeviceRead     uint64 = 1 << 48 // 0x1000000000000 - Read device info
	PermDeviceRegister uint64 = 1 << 49 // 0x2000000000000 - Register devices
	PermDeviceUpdate   uint64 = 1 << 50 // 0x4000000000000 - Update device info
	PermDeviceRevoke   uint64 = 1 << 51 // 0x8000000000000 - Revoke device keys
	PermDeviceRotate   uint64 = 1 << 52 // 0x10000000000000 - Rotate device keys
	PermDeviceDelete   uint64 = 1 << 53 // 0x20000000000000 - Delete devices

	// Administrative Permissions (bits 56-63)
	PermAdminFullAccess   uint64 = 1 << 56 // 0x100000000000000 - Full system access
	PermAdminManageUsers  uint64 = 1 << 57 // 0x200000000000000 - Manage users
	PermAdminManageRoles  uint64 = 1 << 58 // 0x400000000000000 - Manage roles
	PermAdminManagePolicy uint64 = 1 << 59 // 0x800000000000000 - Manage policies
	PermAdminViewAudit    uint64 = 1 << 60 // 0x1000000000000000 - View audit logs
	PermAdminSystemConfig uint64 = 1 << 61 // 0x2000000000000000 - System configuration
	PermAdminEmergencyOps uint64 = 1 << 62 // 0x4000000000000000 - Emergency operations
)

// Permission bit masks for common permission sets
const (
	// Asset permission masks
	PermAssetReadOnly uint64 = PermAssetRead | PermAssetAudit | PermAssetMonitor
	PermAssetOperator uint64 = PermAssetReadOnly | PermAssetControl
	PermAssetManager  uint64 = PermAssetOperator | PermAssetUpdate | PermAssetConfig | PermAssetMaintain
	PermAssetAdmin    uint64 = PermAssetManager | PermAssetCreate | PermAssetDelete | PermAssetGrant | PermAssetRevoke | PermAssetTransfer
	PermAssetAll      uint64 = 0x0000FFFF // All asset permissions (bits 0-15)

	// DID permission masks
	PermDIDReadOnly   uint64 = PermDIDRead
	PermDIDEditor     uint64 = PermDIDReadOnly | PermDIDUpdate | PermDIDUpdateMetadata
	PermDIDKeyManager uint64 = PermDIDEditor | PermDIDAddKey | PermDIDRemoveKey
	PermDIDManager    uint64 = PermDIDKeyManager | PermDIDAddService | PermDIDRemoveService
	PermDIDAdmin      uint64 = PermDIDManager | PermDIDCreate | PermDIDDelete | PermDIDDeactivate
	PermDIDAll        uint64 = 0x03FF0000 // All DID permissions (bits 16-25)

	// Credential permission masks
	PermCredentialReadOnly uint64 = PermCredentialRead | PermCredentialVerify
	PermCredentialIssuer   uint64 = PermCredentialReadOnly | PermCredentialIssue | PermCredentialUpdate
	PermCredentialManager  uint64 = PermCredentialIssuer | PermCredentialRevoke | PermCredentialSuspend | PermCredentialResume
	PermCredentialAdmin    uint64 = PermCredentialManager | PermCredentialAudit
	PermCredentialAll      uint64 = 0x00FF00000000 // All credential permissions (bits 32-39)

	// Device permission masks
	PermDeviceReadOnly uint64 = PermDeviceRead
	PermDeviceOperator uint64 = PermDeviceReadOnly | PermDeviceUpdate | PermDeviceRotate
	PermDeviceAdmin    uint64 = PermDeviceOperator | PermDeviceRegister | PermDeviceRevoke | PermDeviceDelete
	PermDeviceAll      uint64 = 0x003F000000000000 // All device permissions (bits 48-53)

	// Admin permission masks
	PermAdminUserManager   uint64 = PermAdminManageUsers | PermAdminViewAudit
	PermAdminRoleManager   uint64 = PermAdminManageRoles | PermAdminViewAudit
	PermAdminPolicyManager uint64 = PermAdminManagePolicy | PermAdminViewAudit
	PermAdminAll           uint64 = 0xFF00000000000000 // All admin permissions (bits 56-63)

	// Special permission masks
	PermNone         uint64 = 0
	PermAllResources uint64 = 0xFFFFFFFFFFFFFFFF // All permissions
)

// Resource type constants
const (
	ResourceTypeAsset      = "asset"
	ResourceTypeDID        = "did"
	ResourceTypeCredential = "credential"
	ResourceTypeDevice     = "device"
	ResourceTypeZone       = "zone"
	ResourceTypeSystem     = "system"
)

// HasPermission checks if a permission set contains a specific permission
func HasPermission(permissionBits uint64, requiredPermission uint64) bool {
	return (permissionBits & requiredPermission) == requiredPermission
}

// HasAnyPermission checks if a permission set contains any of the specified permissions
func HasAnyPermission(permissionBits uint64, requiredPermissions uint64) bool {
	return (permissionBits & requiredPermissions) != 0
}

// HasAllPermissions checks if a permission set contains all of the specified permissions
func HasAllPermissions(permissionBits uint64, requiredPermissions uint64) bool {
	return (permissionBits & requiredPermissions) == requiredPermissions
}

// AddPermission adds a permission to a permission set
func AddPermission(permissionBits uint64, permissionToAdd uint64) uint64 {
	return permissionBits | permissionToAdd
}

// RemovePermission removes a permission from a permission set
func RemovePermission(permissionBits uint64, permissionToRemove uint64) uint64 {
	return permissionBits &^ permissionToRemove
}

// CombinePermissions combines multiple permission sets using OR
func CombinePermissions(permissions ...uint64) uint64 {
	result := uint64(0)
	for _, perm := range permissions {
		result |= perm
	}
	return result
}

// IntersectPermissions finds common permissions between sets using AND
func IntersectPermissions(permissions ...uint64) uint64 {
	if len(permissions) == 0 {
		return 0
	}
	result := permissions[0]
	for i := 1; i < len(permissions); i++ {
		result &= permissions[i]
	}
	return result
}

// CountPermissions counts the number of individual permissions in a set
func CountPermissions(permissionBits uint64) int {
	count := 0
	for permissionBits != 0 {
		count++
		permissionBits &= permissionBits - 1 // Clear the lowest set bit
	}
	return count
}

// ListSetPermissions returns a slice of individual permission bits that are set
func ListSetPermissions(permissionBits uint64) []uint64 {
	var permissions []uint64
	for bit := uint64(0); bit < 64; bit++ {
		permission := uint64(1) << bit
		if HasPermission(permissionBits, permission) {
			permissions = append(permissions, permission)
		}
	}
	return permissions
}

// GetPermissionName returns the human-readable name for a permission bit
func GetPermissionName(permissionBit uint64) string {
	names := map[uint64]string{
		// Asset permissions
		PermAssetRead:     "asset.read",
		PermAssetUpdate:   "asset.update",
		PermAssetDelete:   "asset.delete",
		PermAssetControl:  "asset.control",
		PermAssetGrant:    "asset.grant",
		PermAssetRevoke:   "asset.revoke",
		PermAssetAudit:    "asset.audit",
		PermAssetMaintain: "asset.maintain",
		PermAssetCreate:   "asset.create",
		PermAssetTransfer: "asset.transfer",
		PermAssetConfig:   "asset.config",
		PermAssetMonitor:  "asset.monitor",

		// DID permissions
		PermDIDRead:           "did.read",
		PermDIDUpdate:         "did.update",
		PermDIDDelete:         "did.delete",
		PermDIDCreate:         "did.create",
		PermDIDDeactivate:     "did.deactivate",
		PermDIDAddKey:         "did.add_key",
		PermDIDRemoveKey:      "did.remove_key",
		PermDIDAddService:     "did.add_service",
		PermDIDRemoveService:  "did.remove_service",
		PermDIDUpdateMetadata: "did.update_metadata",

		// Credential permissions
		PermCredentialRead:    "credential.read",
		PermCredentialIssue:   "credential.issue",
		PermCredentialRevoke:  "credential.revoke",
		PermCredentialVerify:  "credential.verify",
		PermCredentialUpdate:  "credential.update",
		PermCredentialSuspend: "credential.suspend",
		PermCredentialResume:  "credential.resume",
		PermCredentialAudit:   "credential.audit",

		// Device permissions
		PermDeviceRead:     "device.read",
		PermDeviceRegister: "device.register",
		PermDeviceUpdate:   "device.update",
		PermDeviceRevoke:   "device.revoke",
		PermDeviceRotate:   "device.rotate",
		PermDeviceDelete:   "device.delete",

		// Admin permissions
		PermAdminFullAccess:   "admin.full_access",
		PermAdminManageUsers:  "admin.manage_users",
		PermAdminManageRoles:  "admin.manage_roles",
		PermAdminManagePolicy: "admin.manage_policy",
		PermAdminViewAudit:    "admin.view_audit",
		PermAdminSystemConfig: "admin.system_config",
		PermAdminEmergencyOps: "admin.emergency_ops",
	}

	if name, ok := names[permissionBit]; ok {
		return name
	}
	return "unknown"
}

// GetPermissionDescription returns a human-readable description for a permission bit
func GetPermissionDescription(permissionBit uint64) string {
	descriptions := map[uint64]string{
		// Asset permissions
		PermAssetRead:     "Read asset information and status",
		PermAssetUpdate:   "Update asset properties and metadata",
		PermAssetDelete:   "Delete assets from the system",
		PermAssetControl:  "Control asset state (lock/unlock, open/close)",
		PermAssetGrant:    "Grant access permissions to assets",
		PermAssetRevoke:   "Revoke access permissions from assets",
		PermAssetAudit:    "View asset access and modification audit logs",
		PermAssetMaintain: "Perform maintenance operations on assets",
		PermAssetCreate:   "Create new assets in the system",
		PermAssetTransfer: "Transfer asset ownership to another DID",
		PermAssetConfig:   "Configure asset settings and parameters",
		PermAssetMonitor:  "Monitor asset status and receive alerts",

		// DID permissions
		PermDIDRead:           "Read DID documents and their contents",
		PermDIDUpdate:         "Update DID document properties",
		PermDIDDelete:         "Delete DID documents",
		PermDIDCreate:         "Create new DID documents",
		PermDIDDeactivate:     "Deactivate DID documents",
		PermDIDAddKey:         "Add public keys to DID documents",
		PermDIDRemoveKey:      "Remove public keys from DID documents",
		PermDIDAddService:     "Add service endpoints to DID documents",
		PermDIDRemoveService:  "Remove service endpoints from DID documents",
		PermDIDUpdateMetadata: "Update DID document metadata",

		// Credential permissions
		PermCredentialRead:    "Read verifiable credentials",
		PermCredentialIssue:   "Issue new verifiable credentials",
		PermCredentialRevoke:  "Revoke issued credentials",
		PermCredentialVerify:  "Verify credential authenticity and validity",
		PermCredentialUpdate:  "Update credential metadata",
		PermCredentialSuspend: "Temporarily suspend credentials",
		PermCredentialResume:  "Resume suspended credentials",
		PermCredentialAudit:   "View credential issuance and verification audit logs",

		// Device permissions
		PermDeviceRead:     "Read device information and keys",
		PermDeviceRegister: "Register new devices in the system",
		PermDeviceUpdate:   "Update device information and metadata",
		PermDeviceRevoke:   "Revoke device keys and access",
		PermDeviceRotate:   "Rotate device cryptographic keys",
		PermDeviceDelete:   "Delete devices from the system",

		// Admin permissions
		PermAdminFullAccess:   "Full administrative access to all system functions",
		PermAdminManageUsers:  "Manage user accounts and DIDs",
		PermAdminManageRoles:  "Create and manage access control roles",
		PermAdminManagePolicy: "Create and manage access control policies",
		PermAdminViewAudit:    "View all system audit logs and reports",
		PermAdminSystemConfig: "Configure system-wide settings and parameters",
		PermAdminEmergencyOps: "Perform emergency operations and overrides",
	}

	if desc, ok := descriptions[permissionBit]; ok {
		return desc
	}
	return "Unknown permission"
}

// GetPermissionsByResourceType returns all permission bits relevant to a resource type
func GetPermissionsByResourceType(resourceType string) uint64 {
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

// ValidatePermissionBits checks if permission bits are valid for a resource type
func ValidatePermissionBits(resourceType string, permissionBits uint64) bool {
	validBits := GetPermissionsByResourceType(resourceType)
	if resourceType == ResourceTypeSystem {
		// System permissions can include all types
		return true
	}
	// Check that only valid bits for this resource type are set
	return (permissionBits & ^validBits) == 0
}
