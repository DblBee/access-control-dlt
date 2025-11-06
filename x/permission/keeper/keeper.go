package keeper

import (
	"fmt"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"

	"acmain/x/permission/types"
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

	// Permission storage
	Permissions              collections.Map[string, types.Permission]              // key: did:resourceType:resourceID
	DIDPermissionAssignments collections.Map[string, types.DIDPermissionAssignment] // key: did
	RolePermissions          collections.Map[string, types.RolePermission]          // key: roleName:resourceType
	PermissionBitDefinitions collections.Map[string, types.PermissionBitDefinition] // key: resourceType:bitPosition
	PermissionAuditLogs      collections.Map[string, types.PermissionAuditLog]      // key: logID

	// Indexes for efficient queries (using KeySet for simple membership tracking)
	PermissionsByDID          collections.KeySet[collections.Pair[string, string]] // Pair[did, permissionKey]
	PermissionsByResourceType collections.KeySet[collections.Pair[string, string]] // Pair[resourceType, permissionKey]
	PermissionsByResource     collections.KeySet[collections.Pair[string, string]] // Pair[resourceType:resourceID, permissionKey]
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

		Params:                    collections.NewItem(sb, types.ParamsKey, "params", codec.CollValue[types.Params](cdc)),
		Permissions:               collections.NewMap(sb, types.PermissionsKey, "permissions", collections.StringKey, codec.CollValue[types.Permission](cdc)),
		DIDPermissionAssignments:  collections.NewMap(sb, types.DIDPermissionAssignmentsKey, "did_permission_assignments", collections.StringKey, codec.CollValue[types.DIDPermissionAssignment](cdc)),
		RolePermissions:           collections.NewMap(sb, types.RolePermissionsKey, "role_permissions", collections.StringKey, codec.CollValue[types.RolePermission](cdc)),
		PermissionBitDefinitions:  collections.NewMap(sb, types.PermissionBitDefinitionsKey, "permission_bit_definitions", collections.StringKey, codec.CollValue[types.PermissionBitDefinition](cdc)),
		PermissionAuditLogs:       collections.NewMap(sb, types.PermissionAuditLogsKey, "permission_audit_logs", collections.StringKey, codec.CollValue[types.PermissionAuditLog](cdc)),
		PermissionsByDID:          collections.NewKeySet(sb, types.PermissionsByDIDKey, "permissions_by_did", collections.PairKeyCodec(collections.StringKey, collections.StringKey)),
		PermissionsByResourceType: collections.NewKeySet(sb, types.PermissionsByResourceTypeKey, "permissions_by_resource_type", collections.PairKeyCodec(collections.StringKey, collections.StringKey)),
		PermissionsByResource:     collections.NewKeySet(sb, types.PermissionsByResourceKey, "permissions_by_resource", collections.PairKeyCodec(collections.StringKey, collections.StringKey)),
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
