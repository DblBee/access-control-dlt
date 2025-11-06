package keeper

import (
	"context"
	"fmt"
	"time"

	"cosmossdk.io/collections"

	"acmain/x/permission/types"
)

// GrantPermission grants a permission to a DID
func (k Keeper) GrantPermission(ctx context.Context, permission *types.Permission) error {
	// Validate the permission
	if err := permission.Validate(); err != nil {
		return fmt.Errorf("invalid permission: %w", err)
	}

	// Check if permission already exists
	key := makePermissionKey(permission.Did, permission.ResourceType, permission.ResourceId)
	existing, err := k.Permissions.Get(ctx, key)
	if err == nil {
		// Permission exists, merge the bits
		existing.PermissionBits = types.AddPermission(existing.PermissionBits, permission.PermissionBits)
		existing.GrantedBy = permission.GrantedBy
		existing.GrantedAt = time.Now()

		// Update expiration if provided and later than existing
		if permission.ExpiresAt != nil && !permission.ExpiresAt.IsZero() {
			if existing.ExpiresAt == nil || existing.ExpiresAt.IsZero() || permission.ExpiresAt.After(*existing.ExpiresAt) {
				existing.ExpiresAt = permission.ExpiresAt
			}
		}

		// Update metadata
		if existing.Metadata == nil {
			existing.Metadata = make(map[string]string)
		}
		for k, v := range permission.Metadata {
			existing.Metadata[k] = v
		}

		permission = &existing
	}

	// Store the permission
	if err := k.Permissions.Set(ctx, key, *permission); err != nil {
		return fmt.Errorf("failed to store permission: %w", err)
	}

	// Update indexes
	if err := k.addPermissionToIndexes(ctx, key, permission); err != nil {
		return fmt.Errorf("failed to update indexes: %w", err)
	}

	// Log the action
	if err := k.logPermissionAction(ctx, types.PermissionAction_PERMISSION_ACTION_GRANT, permission.GrantedBy, permission.Did, permission.ResourceType, permission.ResourceId, permission.PermissionBits, true, "permission granted"); err != nil {
		return fmt.Errorf("failed to log action: %w", err)
	}

	return nil
}

// RevokePermission revokes a permission from a DID
func (k Keeper) RevokePermission(ctx context.Context, did, resourceType, resourceID, revokedBy string, permissionBits uint64) error {
	key := makePermissionKey(did, resourceType, resourceID)

	permission, err := k.Permissions.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("permission not found: %w", err)
	}

	now := time.Now()
	if permissionBits == types.PermAllResources {
		// Revoke all permissions
		permission.Revoked = true
		permission.RevokedAt = &now
		permission.RevokedBy = revokedBy
	} else {
		// Revoke specific permissions
		permission.PermissionBits = types.RemovePermission(permission.PermissionBits, permissionBits)

		// If no permissions left, mark as revoked
		if permission.PermissionBits == 0 {
			permission.Revoked = true
			permission.RevokedAt = &now
			permission.RevokedBy = revokedBy
		}
	}

	if err := k.Permissions.Set(ctx, key, permission); err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}

	// Log the action
	if err := k.logPermissionAction(ctx, types.PermissionAction_PERMISSION_ACTION_REVOKE, revokedBy, did, resourceType, resourceID, permissionBits, true, "permission revoked"); err != nil {
		return fmt.Errorf("failed to log action: %w", err)
	}

	return nil
}

// CheckPermission checks if a DID has a specific permission for a resource
func (k Keeper) CheckPermission(ctx context.Context, did, resourceType, resourceID string, requiredPermission uint64) (bool, error) {
	// Check specific resource permission first
	if resourceID != "" {
		key := makePermissionKey(did, resourceType, resourceID)
		if permission, err := k.Permissions.Get(ctx, key); err == nil && permission.IsActive() {
			if types.HasPermission(permission.PermissionBits, requiredPermission) {
				// Check conditions
				if k.checkPermissionConditions(ctx, &permission) {
					k.logPermissionAction(ctx, types.PermissionAction_PERMISSION_ACTION_CHECK, did, did, resourceType, resourceID, requiredPermission, true, "permission check succeeded")
					return true, nil
				}
			}
		}
	}

	// Check wildcard permission (all resources of this type)
	wildcardKey := makePermissionKey(did, resourceType, "")
	if permission, err := k.Permissions.Get(ctx, wildcardKey); err == nil && permission.IsActive() {
		if types.HasPermission(permission.PermissionBits, requiredPermission) {
			// Check conditions
			if k.checkPermissionConditions(ctx, &permission) {
				k.logPermissionAction(ctx, types.PermissionAction_PERMISSION_ACTION_CHECK, did, did, resourceType, resourceID, requiredPermission, true, "permission check succeeded (wildcard)")
				return true, nil
			}
		}
	}

	// Check role-based permissions
	assignment, err := k.DIDPermissionAssignments.Get(ctx, did)
	if err == nil {
		for _, roleName := range assignment.Roles {
			roleKey := makeRolePermissionKey(roleName, resourceType)
			if role, err := k.RolePermissions.Get(ctx, roleKey); err == nil {
				if types.HasPermission(role.PermissionBits, requiredPermission) {
					k.logPermissionAction(ctx, types.PermissionAction_PERMISSION_ACTION_CHECK, did, did, resourceType, resourceID, requiredPermission, true, fmt.Sprintf("permission check succeeded (role: %s)", roleName))
					return true, nil
				}
			}
		}
	}

	k.logPermissionAction(ctx, types.PermissionAction_PERMISSION_ACTION_CHECK, did, did, resourceType, resourceID, requiredPermission, false, "permission check failed")
	return false, nil
}

// GetPermissionsForDID returns all permissions for a specific DID
func (k Keeper) GetPermissionsForDID(ctx context.Context, did string) ([]types.Permission, error) {
	var permissions []types.Permission

	// Iterate over all permissions in the KeySet for this DID
	rng := collections.NewPrefixedPairRange[string, string](did)
	err := k.PermissionsByDID.Walk(ctx, rng, func(key collections.Pair[string, string]) (stop bool, err error) {
		permissionKey := key.K2()
		permission, err := k.Permissions.Get(ctx, permissionKey)
		if err == nil {
			permissions = append(permissions, permission)
		}
		return false, nil
	})

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

// GetPermissionsForResource returns all permissions for a specific resource
func (k Keeper) GetPermissionsForResource(ctx context.Context, resourceType, resourceID string) ([]types.Permission, error) {
	resourceKey := makeResourceKey(resourceType, resourceID)
	var permissions []types.Permission

	// Iterate over all permissions in the KeySet for this resource
	rng := collections.NewPrefixedPairRange[string, string](resourceKey)
	err := k.PermissionsByResource.Walk(ctx, rng, func(key collections.Pair[string, string]) (stop bool, err error) {
		permissionKey := key.K2()
		permission, err := k.Permissions.Get(ctx, permissionKey)
		if err == nil {
			permissions = append(permissions, permission)
		}
		return false, nil
	})

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

// CreateRole creates a new role with permission bits
func (k Keeper) CreateRole(ctx context.Context, role *types.RolePermission) error {
	if err := role.Validate(); err != nil {
		return fmt.Errorf("invalid role: %w", err)
	}

	key := makeRolePermissionKey(role.RoleName, role.ResourceType)

	// Check if role already exists
	if _, err := k.RolePermissions.Get(ctx, key); err == nil {
		return fmt.Errorf("role %s already exists for resource type %s", role.RoleName, role.ResourceType)
	}

	role.CreatedAt = time.Now()
	if err := k.RolePermissions.Set(ctx, key, *role); err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// UpdateRole updates an existing role's permission bits
func (k Keeper) UpdateRole(ctx context.Context, roleName, resourceType, updatedBy string, permissionBits uint64) error {
	key := makeRolePermissionKey(roleName, resourceType)

	role, err := k.RolePermissions.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	now := time.Now()
	role.PermissionBits = permissionBits
	role.UpdatedAt = &now

	if err := k.RolePermissions.Set(ctx, key, role); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	return nil
}

// AssignRole assigns a role to a DID
func (k Keeper) AssignRole(ctx context.Context, did, roleName, assignedBy string) error {
	// Get or create DID permission assignment
	assignment, err := k.DIDPermissionAssignments.Get(ctx, did)
	if err != nil {
		// Create new assignment
		assignment = types.DIDPermissionAssignment{
			Did:       did,
			Roles:     []string{roleName},
			CreatedAt: time.Now(),
		}
	} else {
		// Check if role already assigned
		for _, r := range assignment.Roles {
			if r == roleName {
				return fmt.Errorf("role %s already assigned to DID %s", roleName, did)
			}
		}
		assignment.Roles = append(assignment.Roles, roleName)
		now := time.Now()
		assignment.UpdatedAt = &now
	}

	if err := k.DIDPermissionAssignments.Set(ctx, did, assignment); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	// Log the action
	if err := k.logPermissionAction(ctx, types.PermissionAction_PERMISSION_ACTION_ROLE_ASSIGN, assignedBy, did, "role", roleName, 0, true, fmt.Sprintf("role %s assigned", roleName)); err != nil {
		return fmt.Errorf("failed to log action: %w", err)
	}

	return nil
}

// RemoveRole removes a role from a DID
func (k Keeper) RemoveRole(ctx context.Context, did, roleName, removedBy string) error {
	assignment, err := k.DIDPermissionAssignments.Get(ctx, did)
	if err != nil {
		return fmt.Errorf("DID permission assignment not found: %w", err)
	}

	// Find and remove the role
	found := false
	newRoles := make([]string, 0, len(assignment.Roles))
	for _, r := range assignment.Roles {
		if r != roleName {
			newRoles = append(newRoles, r)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("role %s not assigned to DID %s", roleName, did)
	}

	assignment.Roles = newRoles
	now := time.Now()
	assignment.UpdatedAt = &now

	if err := k.DIDPermissionAssignments.Set(ctx, did, assignment); err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	// Log the action
	if err := k.logPermissionAction(ctx, types.PermissionAction_PERMISSION_ACTION_ROLE_REMOVE, removedBy, did, "role", roleName, 0, true, fmt.Sprintf("role %s removed", roleName)); err != nil {
		return fmt.Errorf("failed to log action: %w", err)
	}

	return nil
}

// GetEffectivePermissions returns the combined permissions for a DID (direct + role-based)
func (k Keeper) GetEffectivePermissions(ctx context.Context, did, resourceType, resourceID string) (uint64, error) {
	effectivePerms := uint64(0)

	// Get direct permissions
	if resourceID != "" {
		key := makePermissionKey(did, resourceType, resourceID)
		if permission, err := k.Permissions.Get(ctx, key); err == nil && permission.IsActive() {
			if k.checkPermissionConditions(ctx, &permission) {
				effectivePerms = types.CombinePermissions(effectivePerms, permission.PermissionBits)
			}
		}
	}

	// Get wildcard permissions
	wildcardKey := makePermissionKey(did, resourceType, "")
	if permission, err := k.Permissions.Get(ctx, wildcardKey); err == nil && permission.IsActive() {
		if k.checkPermissionConditions(ctx, &permission) {
			effectivePerms = types.CombinePermissions(effectivePerms, permission.PermissionBits)
		}
	}

	// Get role-based permissions
	assignment, err := k.DIDPermissionAssignments.Get(ctx, did)
	if err == nil {
		for _, roleName := range assignment.Roles {
			roleKey := makeRolePermissionKey(roleName, resourceType)
			if role, err := k.RolePermissions.Get(ctx, roleKey); err == nil {
				effectivePerms = types.CombinePermissions(effectivePerms, role.PermissionBits)
			}
		}
	}

	return effectivePerms, nil
}

// Helper functions

func makePermissionKey(did, resourceType, resourceID string) string {
	return fmt.Sprintf("%s:%s:%s", did, resourceType, resourceID)
}

func makeResourceKey(resourceType, resourceID string) string {
	return fmt.Sprintf("%s:%s", resourceType, resourceID)
}

func makeRolePermissionKey(roleName, resourceType string) string {
	return fmt.Sprintf("%s:%s", roleName, resourceType)
}

func (k Keeper) addPermissionToIndexes(ctx context.Context, key string, permission *types.Permission) error {
	// Add to DID index
	if err := k.PermissionsByDID.Set(ctx, collections.Join(permission.Did, key)); err != nil {
		return err
	}

	// Add to resource type index
	if err := k.PermissionsByResourceType.Set(ctx, collections.Join(permission.ResourceType, key)); err != nil {
		return err
	}

	// Add to specific resource index
	resourceKey := makeResourceKey(permission.ResourceType, permission.ResourceId)
	return k.PermissionsByResource.Set(ctx, collections.Join(resourceKey, key))
}

func (k Keeper) checkPermissionConditions(ctx context.Context, permission *types.Permission) bool {
	// TODO: Implement condition checking based on condition types
	// For now, return true if no conditions or conditions are not implemented
	return len(permission.Conditions) == 0
}

func (k Keeper) logPermissionAction(ctx context.Context, action types.PermissionAction, actorDID, subjectDID, resourceType, resourceID string, permissionBits uint64, result bool, reason string) error {
	log := types.PermissionAuditLog{
		Id:             fmt.Sprintf("%s-%d", actorDID, time.Now().UnixNano()),
		Action:         action,
		ActorDid:       actorDID,
		SubjectDid:     subjectDID,
		ResourceType:   resourceType,
		ResourceId:     resourceID,
		PermissionBits: permissionBits,
		Result:         result,
		Reason:         reason,
		Timestamp:      time.Now(),
	}

	return k.PermissionAuditLogs.Set(ctx, log.Id, log)
}
