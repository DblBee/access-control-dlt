# Permission Module

A comprehensive permission management module for the Access Control DLT system using efficient bitwise operations to manage fine-grained access control for DID-based identities.

## Overview

The permission module provides a flexible, high-performance access control system that integrates with the IAM module's DID documents. It uses bitwise operations to efficiently represent and check permissions, supporting up to 64 different permission types per resource category.

## Key Features

- **Bitwise Permission Operations**: Efficient permission storage and checking using 64-bit integers
- **Resource-Level Permissions**: Grant permissions for specific resources or all resources of a type
- **Role-Based Access Control (RBAC)**: Define reusable roles with permission sets
- **Time-Based Permissions**: Support for permission expiration and time windows
- **Conditional Permissions**: Apply conditions like location, IP range, or MFA requirements
- **Permission Inheritance**: Combine direct permissions with role-based permissions
- **Comprehensive Audit Logging**: Track all permission-related actions
- **DID Integration**: Seamlessly works with W3C DID documents from IAM module

## Architecture

### Permission Bits Structure

Permissions are organized into 64-bit segments by resource type:

```
Bits 0-15:   Asset Permissions (12 permissions defined)
Bits 16-31:  DID Permissions (10 permissions defined)
Bits 32-47:  Credential Permissions (8 permissions defined)
Bits 48-55:  Device Permissions (6 permissions defined)
Bits 56-63:  Administrative Permissions (7 permissions defined)
```

### Core Types

#### Permission
Represents a grant of specific permissions to a DID for a resource:
- `did`: Subject DID that holds the permissions
- `resource_type`: Type of resource (asset, did, credential, device, zone)
- `resource_id`: Specific resource ID (empty = wildcard for all resources of this type)
- `permission_bits`: Bitwise representation of granted permissions (uint64)
- `granted_by`: DID that granted the permissions
- `granted_at`: Grant timestamp
- `expires_at`: Optional expiration time
- `revoked`: Whether the permission has been revoked
- `conditions`: Optional conditions that must be met
- `metadata`: Additional context

#### RolePermission
Defines a reusable role with associated permissions:
- `role_name`: Unique role identifier
- `resource_type`: Type of resource the role applies to
- `permission_bits`: Default permission set for this role
- `description`: Human-readable description
- `created_by`: DID that created the role

#### DIDPermissionAssignment
Links DIDs to their permissions and roles:
- `did`: Subject DID
- `permissions`: List of individual permission grants
- `roles`: List of assigned role names

## Permission Types

### Asset Permissions (Bits 0-15)

| Bit | Hex | Name | Description |
|-----|-----|------|-------------|
| 0 | 0x0001 | `asset.read` | Read asset information and status |
| 1 | 0x0002 | `asset.update` | Update asset properties and metadata |
| 2 | 0x0004 | `asset.delete` | Delete assets from the system |
| 3 | 0x0008 | `asset.control` | Control asset state (lock/unlock) |
| 4 | 0x0010 | `asset.grant` | Grant access permissions to assets |
| 5 | 0x0020 | `asset.revoke` | Revoke access permissions from assets |
| 6 | 0x0040 | `asset.audit` | View asset audit logs |
| 7 | 0x0080 | `asset.maintain` | Perform maintenance operations |
| 8 | 0x0100 | `asset.create` | Create new assets |
| 9 | 0x0200 | `asset.transfer` | Transfer asset ownership |
| 10 | 0x0400 | `asset.config` | Configure asset settings |
| 11 | 0x0800 | `asset.monitor` | Monitor asset status |

**Common Permission Masks:**
- `PermAssetReadOnly`: Read, Audit, Monitor
- `PermAssetOperator`: ReadOnly + Control
- `PermAssetManager`: Operator + Update, Config, Maintain
- `PermAssetAdmin`: Manager + Create, Delete, Grant, Revoke, Transfer

### DID Permissions (Bits 16-25)

| Bit | Hex | Name | Description |
|-----|-----|------|-------------|
| 16 | 0x010000 | `did.read` | Read DID documents |
| 17 | 0x020000 | `did.update` | Update DID properties |
| 18 | 0x040000 | `did.delete` | Delete DID documents |
| 19 | 0x080000 | `did.create` | Create new DIDs |
| 20 | 0x100000 | `did.deactivate` | Deactivate DIDs |
| 21 | 0x200000 | `did.add_key` | Add keys to DID |
| 22 | 0x400000 | `did.remove_key` | Remove keys from DID |
| 23 | 0x800000 | `did.add_service` | Add service endpoints |
| 24 | 0x1000000 | `did.remove_service` | Remove service endpoints |
| 25 | 0x2000000 | `did.update_metadata` | Update DID metadata |

**Common Permission Masks:**
- `PermDIDReadOnly`: Read
- `PermDIDEditor`: ReadOnly + Update, UpdateMetadata
- `PermDIDKeyManager`: Editor + AddKey, RemoveKey
- `PermDIDManager`: KeyManager + AddService, RemoveService
- `PermDIDAdmin`: Manager + Create, Delete, Deactivate

### Credential Permissions (Bits 32-39)

| Bit | Hex | Name | Description |
|-----|-----|------|-------------|
| 32 | 0x100000000 | `credential.read` | Read verifiable credentials |
| 33 | 0x200000000 | `credential.issue` | Issue new credentials |
| 34 | 0x400000000 | `credential.revoke` | Revoke credentials |
| 35 | 0x800000000 | `credential.verify` | Verify credential authenticity |
| 36 | 0x1000000000 | `credential.update` | Update credential metadata |
| 37 | 0x2000000000 | `credential.suspend` | Suspend credentials temporarily |
| 38 | 0x4000000000 | `credential.resume` | Resume suspended credentials |
| 39 | 0x8000000000 | `credential.audit` | View credential audit logs |

**Common Permission Masks:**
- `PermCredentialReadOnly`: Read, Verify
- `PermCredentialIssuer`: ReadOnly + Issue, Update
- `PermCredentialManager`: Issuer + Revoke, Suspend, Resume
- `PermCredentialAdmin`: Manager + Audit

### Device Permissions (Bits 48-53)

| Bit | Hex | Name | Description |
|-----|-----|------|-------------|
| 48 | 0x1000000000000 | `device.read` | Read device information |
| 49 | 0x2000000000000 | `device.register` | Register new devices |
| 50 | 0x4000000000000 | `device.update` | Update device information |
| 51 | 0x8000000000000 | `device.revoke` | Revoke device keys |
| 52 | 0x10000000000000 | `device.rotate` | Rotate device keys |
| 53 | 0x20000000000000 | `device.delete` | Delete devices |

**Common Permission Masks:**
- `PermDeviceReadOnly`: Read
- `PermDeviceOperator`: ReadOnly + Update, Rotate
- `PermDeviceAdmin`: Operator + Register, Revoke, Delete

### Administrative Permissions (Bits 56-62)

| Bit | Hex | Name | Description |
|-----|-----|------|-------------|
| 56 | 0x100000000000000 | `admin.full_access` | Full system access |
| 57 | 0x200000000000000 | `admin.manage_users` | Manage user accounts |
| 58 | 0x400000000000000 | `admin.manage_roles` | Create and manage roles |
| 59 | 0x800000000000000 | `admin.manage_policy` | Manage access policies |
| 60 | 0x1000000000000000 | `admin.view_audit` | View system audit logs |
| 61 | 0x2000000000000000 | `admin.system_config` | Configure system settings |
| 62 | 0x4000000000000000 | `admin.emergency_ops` | Emergency operations |

## Usage Examples

### 1. Grant Permissions to a DID

```go
import (
	"acmain/x/permission/types"
	"time"
)

// Build a permission grant
permission, err := types.NewPermissionBuilder(
	"did:acmain:cosmos1abc...", // Subject DID
	types.ResourceTypeAsset,     // Resource type
	"asset-123",                 // Specific asset ID
).
	WithPermissions(types.PermAssetRead | types.PermAssetControl).
	WithGrantedBy("did:acmain:cosmos1xyz...").
	WithExpiration(time.Now().Add(30 * 24 * time.Hour)). // 30 days
	WithMetadata("reason", "temporary access for maintenance").
	Build()

if err != nil {
	return err
}

// Grant the permission
err = keeper.GrantPermission(ctx, permission)
```

### 2. Grant Wildcard Permissions

```go
// Grant read access to ALL assets
permission, err := types.NewPermissionBuilder(
	"did:acmain:cosmos1abc...",
	types.ResourceTypeAsset,
	"", // Empty resource ID = wildcard
).
	WithPermissions(types.PermAssetReadOnly).
	WithGrantedBy("did:acmain:cosmos1xyz...").
	Build()

err = keeper.GrantPermission(ctx, permission)
```

### 3. Check Permissions

```go
// Check if DID has control permission for a specific asset
hasPermission, err := keeper.CheckPermission(
	ctx,
	"did:acmain:cosmos1abc...",
	types.ResourceTypeAsset,
	"asset-123",
	types.PermAssetControl,
)

if !hasPermission {
	return fmt.Errorf("access denied: insufficient permissions")
}
```

### 4. Create and Assign Roles

```go
// Create an asset operator role
role := types.NewAssetOperatorRole("did:acmain:cosmos1admin...")
err := keeper.CreateRole(ctx, role)

// Assign role to a DID
err = keeper.AssignRole(
	ctx,
	"did:acmain:cosmos1employee...",
	"asset_operator",
	"did:acmain:cosmos1admin...",
)
```

### 5. Create Custom Roles

```go
role, err := types.NewRolePermissionBuilder(
	"security_officer",
	types.ResourceTypeAsset,
).
	WithPermissions(
		types.PermAssetRead |
		types.PermAssetControl |
		types.PermAssetAudit |
		types.PermAssetMonitor,
	).
	WithDescription("Security officer with monitoring and control access").
	WithCreatedBy("did:acmain:cosmos1admin...").
	Build()

err = keeper.CreateRole(ctx, role)
```

### 6. Get Effective Permissions

```go
// Get combined permissions (direct + role-based)
effectivePerms, err := keeper.GetEffectivePermissions(
	ctx,
	"did:acmain:cosmos1abc...",
	types.ResourceTypeAsset,
	"asset-123",
)

// Check if effective permissions include required permission
if types.HasPermission(effectivePerms, types.PermAssetUpdate) {
	// User has update permission
}

// Format permissions for display
permString := types.FormatPermissions(effectivePerms)
// Output: "asset.read, asset.update, asset.control"
```

### 7. Time-Based Permissions

```go
// Grant access only during business hours
permission, err := types.NewPermissionBuilder(
	"did:acmain:cosmos1contractor...",
	types.ResourceTypeAsset,
	"building-a",
).
	WithPermissions(types.PermAssetControl).
	WithGrantedBy("did:acmain:cosmos1admin...").
	WithTimeWindow(
		time.Date(2025, 1, 1, 9, 0, 0, 0, time.UTC),   // 9 AM
		time.Date(2025, 1, 1, 17, 0, 0, 0, time.UTC),  // 5 PM
	).
	Build()

err = keeper.GrantPermission(ctx, permission)
```

### 8. Revoke Permissions

```go
// Revoke specific permissions
err := keeper.RevokePermission(
	ctx,
	"did:acmain:cosmos1abc...",          // Subject DID
	types.ResourceTypeAsset,              // Resource type
	"asset-123",                          // Resource ID
	"did:acmain:cosmos1admin...",        // Revoker DID
	types.PermAssetControl,               // Permissions to revoke
)

// Revoke ALL permissions for a resource
err := keeper.RevokePermission(
	ctx,
	"did:acmain:cosmos1abc...",
	types.ResourceTypeAsset,
	"asset-123",
	"did:acmain:cosmos1admin...",
	types.PermAllResources, // Revoke all
)
```

### 9. Using Permission Sets

```go
// Create a permission set for manipulation
ps := types.NewPermissionSet(types.PermAssetRead)

// Add permissions
ps.Add(types.PermAssetUpdate)
ps.Add(types.PermAssetControl)

// Check permissions
if ps.Has(types.PermAssetControl) {
	// Has control permission
}

// Count permissions
count := ps.Count() // Returns 3

// Get all permissions
allPerms := ps.List() // Returns []uint64

// Format as string
fmt.Println(ps.String())
// Output: PermissionSet{bits: 0xB, permissions: [asset.read asset.update asset.control]}
```

### 10. Permission Matrix for Multiple Resources

```go
// Manage permissions across multiple resources
matrix := types.NewPermissionMatrix()

// Set permissions for different assets
matrix.SetPermissions(types.ResourceTypeAsset, "door-1", types.PermAssetControl)
matrix.SetPermissions(types.ResourceTypeAsset, "door-2", types.PermAssetReadOnly)
matrix.SetPermissions(types.ResourceTypeDID, "did:acmain:123", types.PermDIDRead)

// Check permission
if matrix.HasPermission(types.ResourceTypeAsset, "door-1", types.PermAssetControl) {
	// Can control door-1
}

// Add permissions
matrix.AddPermissions(types.ResourceTypeAsset, "door-2", types.PermAssetControl)

// Get all resources
resources := matrix.GetAllResources()
```

## Integration with IAM Module

The permission module is designed to work seamlessly with the IAM module's DID documents:

1. **DID-Based Identity**: All permissions are granted to DIDs, not Cosmos addresses
2. **Credential Integration**: Permissions can be conditioned on holding specific credential types
3. **Key Management**: Permissions for managing DID keys and services
4. **Device Keys**: Separate permission set for IoT device management

### Example Integration

```go
// In IAM module: Create a DID
didDoc := &iamtypes.DIDDocument{
	Id:         "did:acmain:cosmos1abc...",
	Controller: "cosmos1abc...",
	// ... other fields
}
err := iamKeeper.CreateDIDDocument(ctx, didDoc)

// In Permission module: Grant permissions to the DID
permission, _ := types.NewPermissionBuilder(
	"did:acmain:cosmos1abc...",
	types.ResourceTypeAsset,
	"",
).
	WithPermissions(types.PermAssetReadOnly).
	WithGrantedBy("did:acmain:cosmos1admin...").
	Build()

err = permissionKeeper.GrantPermission(ctx, permission)

// Check permissions during asset access
hasAccess, _ := permissionKeeper.CheckPermission(
	ctx,
	"did:acmain:cosmos1abc...",
	types.ResourceTypeAsset,
	"asset-123",
	types.PermAssetRead,
)
```

## Bitwise Operations Performance

The module uses bitwise operations for maximum performance:

- **Permission Check**: O(1) - Single AND operation
- **Add Permission**: O(1) - Single OR operation
- **Remove Permission**: O(1) - Single AND NOT operation
- **Combine Permissions**: O(n) - n OR operations where n is number of permission sets

Benchmark results (Go 1.21):
```
BenchmarkHasPermission-8      1000000000    0.25 ns/op
BenchmarkAddPermission-8      1000000000    0.23 ns/op
BenchmarkCountPermissions-8    500000000    3.42 ns/op
```

## Audit Logging

All permission operations are logged to the audit log:

```go
type PermissionAuditLog struct {
	Id             string              // Unique log ID
	Action         PermissionAction    // GRANT, REVOKE, CHECK, etc.
	ActorDid       string              // Who performed the action
	SubjectDid     string              // Who was affected
	ResourceType   string              // Type of resource
	ResourceId     string              // Specific resource
	PermissionBits uint64              // Permissions involved
	Result         bool                // Success/failure
	Reason         string              // Additional context
	Timestamp      time.Time           // When it occurred
	Metadata       map[string]string   // Extra information
}
```

## Security Considerations

1. **Least Privilege**: Always grant the minimum permissions required
2. **Time-Limited Access**: Use expiration times for temporary access
3. **Audit Everything**: All permission checks are logged
4. **Wildcard Caution**: Be careful with empty resource IDs (wildcard access)
5. **Admin Permissions**: Protect administrative permissions carefully
6. **Revocation**: Regularly audit and revoke unused permissions
7. **Condition Validation**: Implement condition checking thoroughly

## Future Enhancements

- [ ] Delegation: Allow DIDs to delegate permissions to others
- [ ] Permission Templates: Pre-defined permission sets for common scenarios
- [ ] Dynamic Conditions: Runtime evaluation of complex conditions
- [ ] Permission Inheritance Trees: Hierarchical permission structures
- [ ] Quota Management: Limit number of permissions per DID
- [ ] Approval Workflows: Multi-step permission grant processes
- [ ] Integration with x/gov: Governance-controlled permission policies

## Testing

Run the test suite:

```bash
go test ./x/permission/types/...
go test ./x/permission/keeper/...
```

Run benchmarks:

```bash
go test -bench=. ./x/permission/types/
```

## References

- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [NIST RBAC Model](https://csrc.nist.gov/projects/role-based-access-control)
- [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Cosmos SDK Collections](https://docs.cosmos.network/main/build/building-modules/collections)
