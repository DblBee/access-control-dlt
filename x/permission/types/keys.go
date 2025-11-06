package types

import "cosmossdk.io/collections"

const (
	// ModuleName defines the module name
	ModuleName = "permission"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// GovModuleName duplicates the gov module's name to avoid a dependency with x/gov.
	// It should be synced with the gov module's name if it is ever changed.
	// See: https://github.com/cosmos/cosmos-sdk/blob/v0.52.0-beta.2/x/gov/types/keys.go#L9
	GovModuleName = "gov"
)

// Collection keys
var (
	ParamsKey                    = collections.NewPrefix("p_permission")
	PermissionsKey               = collections.NewPrefix("permissions")
	DIDPermissionAssignmentsKey  = collections.NewPrefix("did_assignments")
	RolePermissionsKey           = collections.NewPrefix("roles")
	PermissionBitDefinitionsKey  = collections.NewPrefix("bit_defs")
	PermissionAuditLogsKey       = collections.NewPrefix("audit_logs")
	PermissionsByDIDKey          = collections.NewPrefix("idx_did")
	PermissionsByResourceTypeKey = collections.NewPrefix("idx_res_type")
	PermissionsByResourceKey     = collections.NewPrefix("idx_resource")
)
