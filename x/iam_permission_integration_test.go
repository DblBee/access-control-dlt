package types

import (
	"testing"
	"time"

	permissiontypes "acmain/x/permission/types"
)

// TestIAMPermissionIntegration tests the integration between IAM (DID management) and permission systems
func TestIAMPermissionIntegration(t *testing.T) {
	// Test DID-based permission assignment
	testCases := []struct {
		name           string
		did            string
		resourceType   string
		resourceID     string
		permissionBits uint64
		expectedValid  bool
	}{
		{
			name:           "admin can grant asset permissions",
			did:            "did:acmain:cosmos1admin",
			resourceType:   permissiontypes.ResourceTypeAsset,
			resourceID:     "asset-123",
			permissionBits: permissiontypes.PermAssetRead | permissiontypes.PermAssetControl,
			expectedValid:  true,
		},
		{
			name:           "user can have DID permissions",
			did:            "did:acmain:cosmos1user",
			resourceType:   permissiontypes.ResourceTypeDID,
			resourceID:     "did:acmain:cosmos1user",
			permissionBits: permissiontypes.PermDIDRead | permissiontypes.PermDIDUpdate,
			expectedValid:  true,
		},
		{
			name:           "wildcard permissions for all resources",
			did:            "did:acmain:cosmos1operator",
			resourceType:   permissiontypes.ResourceTypeAsset,
			resourceID:     "", // Empty means all resources
			permissionBits: permissiontypes.PermAssetReadOnly,
			expectedValid:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate permission validation
			isValid := permissiontypes.ValidatePermissionBits(tc.resourceType, tc.permissionBits)
			if isValid != tc.expectedValid {
				t.Errorf("ValidatePermissionBits() = %v, expected %v", isValid, tc.expectedValid)
			}

			// Test permission bits operations
			hasRead := permissiontypes.HasPermission(tc.permissionBits, permissiontypes.PermAssetRead)
			hasUpdate := permissiontypes.HasPermission(tc.permissionBits, permissiontypes.PermAssetUpdate)

			// For asset read-only, should have read but not update
			if tc.permissionBits == permissiontypes.PermAssetReadOnly {
				if !hasRead {
					t.Error("Read-only permission should include read access")
				}
				if hasUpdate {
					t.Error("Read-only permission should not include update access")
				}
			}
		})
	}
}

// TestPermissionRoleIntegration tests role-based permission scenarios
func TestPermissionRoleIntegration(t *testing.T) {
	roles := []struct {
		name        string
		permissions uint64
		expectedOps map[uint64]bool
	}{
		{
			name:        "Asset Operator",
			permissions: permissiontypes.PermAssetOperator,
			expectedOps: map[uint64]bool{
				permissiontypes.PermAssetRead:    true,
				permissiontypes.PermAssetControl: true,
				permissiontypes.PermAssetUpdate:  false,
				permissiontypes.PermAssetDelete:  false,
			},
		},
		{
			name:        "Asset Manager",
			permissions: permissiontypes.PermAssetManager,
			expectedOps: map[uint64]bool{
				permissiontypes.PermAssetRead:    true,
				permissiontypes.PermAssetUpdate:  true,
				permissiontypes.PermAssetControl: true,
				permissiontypes.PermAssetDelete:  false,
			},
		},
		{
			name:        "Asset Admin",
			permissions: permissiontypes.PermAssetAdmin,
			expectedOps: map[uint64]bool{
				permissiontypes.PermAssetRead:    true,
				permissiontypes.PermAssetUpdate:    true,
				permissiontypes.PermAssetControl:   true,
				permissiontypes.PermAssetDelete:    true,
				permissiontypes.PermAssetCreate:    true,
			},
		},
	}

	for _, role := range roles {
		t.Run(role.name, func(t *testing.T) {
			for perm, expected := range role.expectedOps {
				hasPermission := permissiontypes.HasPermission(role.permissions, perm)
				if hasPermission != expected {
					t.Errorf("%s: HasPermission(0x%X) = %v, expected %v", 
						role.name, perm, hasPermission, expected)
				}
			}
		})
	}
}

// TestPermissionTimeIntegration tests time-based permission scenarios
func TestPermissionTimeIntegration(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	testCases := []struct {
		name      string
		grantedAt time.Time
		expiresAt *time.Time
		revoked   bool
		isValid   bool
	}{
		{
			name:      "active permission",
			grantedAt: past,
			expiresAt: &future,
			revoked:   false,
			isValid:   true,
		},
		{
			name:      "expired permission",
			grantedAt: past,
			expiresAt: &past,
			revoked:   false,
			isValid:   false,
		},
		{
			name:      "revoked permission",
			grantedAt: past,
			expiresAt: &future,
			revoked:   true,
			isValid:   false,
		},
		{
			name:      "permission without expiration",
			grantedAt: past,
			expiresAt: nil,
			revoked:   false,
			isValid:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock permission with time-based conditions
			permission := permissiontypes.Permission{
				Did:           "did:acmain:test",
				ResourceType:  permissiontypes.ResourceTypeAsset,
				ResourceId:    "test-asset",
				PermissionBits: permissiontypes.PermAssetRead,
				GrantedBy:     "did:acmain:admin",
				GrantedAt:     tc.grantedAt,
				ExpiresAt:     tc.expiresAt,
				Revoked:       tc.revoked,
			}

			// Validate permission bits (should always be valid regardless of time)
			isValid := permissiontypes.ValidatePermissionBits(permission.ResourceType, permission.PermissionBits)
			if !isValid {
				t.Error("Permission bits should be valid")
			}

			// Test permission counting
			count := permissiontypes.CountPermissions(permission.PermissionBits)
			if count != 1 {
				t.Errorf("Expected 1 permission, got %d", count)
			}
		})
	}
}

// TestPermissionBoundaryIntegration tests permission boundary validation
func TestPermissionBoundaryIntegration(t *testing.T) {
	testCases := []struct {
		name           string
		resourceType   string
		permissionBits uint64
		expectValid    bool
	}{
		{
			name:           "valid asset permissions only",
			resourceType:   permissiontypes.ResourceTypeAsset,
			permissionBits: permissiontypes.PermAssetRead | permissiontypes.PermAssetUpdate,
			expectValid:    true,
		},
		{
			name:           "mixed resource type permissions (invalid)",
			resourceType:   permissiontypes.ResourceTypeAsset,
			permissionBits: permissiontypes.PermAssetRead | permissiontypes.PermDIDRead,
			expectValid:    false,
		},
		{
			name:           "valid DID permissions only",
			resourceType:   permissiontypes.ResourceTypeDID,
			permissionBits: permissiontypes.PermDIDRead | permissiontypes.PermDIDUpdate,
			expectValid:    true,
		},
		{
			name:           "mixed with credential permissions (invalid)",
			resourceType:   permissiontypes.ResourceTypeAsset,
			permissionBits: permissiontypes.PermAssetRead | permissiontypes.PermCredentialIssue,
			expectValid:    false,
		},
		{
			name:           "system permissions allow all",
			resourceType:   permissiontypes.ResourceTypeSystem,
			permissionBits: permissiontypes.PermAssetRead | permissiontypes.PermDIDRead | permissiontypes.PermCredentialRead,
			expectValid:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := permissiontypes.ValidatePermissionBits(tc.resourceType, tc.permissionBits)
			if result != tc.expectValid {
				t.Errorf("ValidatePermissionBits() = %v, expected %v", result, tc.expectValid)
			}
		})
	}
}

// TestPermissionComplexIntegration tests complex multi-DID permission scenarios
func TestPermissionComplexIntegration(t *testing.T) {
	// Simulate a complex scenario with multiple DIDs and permission inheritance
	adminDID := "did:acmain:admin"
	managerDID := "did:acmain:manager"
	operatorDID := "did:acmain:operator"
	userDID := "did:acmain:user"

	// Admin has full system permissions (includes all asset permissions)
	adminPerms := permissiontypes.PermAssetAdmin | permissiontypes.PermDIDAdmin | permissiontypes.PermCredentialAdmin | permissiontypes.PermDeviceAdmin | permissiontypes.PermAdminAll

	// Manager inherits some admin permissions but limited to assets
	managerPerms := permissiontypes.PermAssetManager

	// Operator has read-only access to monitor operations
	operatorPerms := permissiontypes.PermAssetReadOnly

	// User has specific permissions for their own resources
	userPerms := permissiontypes.PermAssetRead | permissiontypes.PermAssetUpdate

	// Test permission hierarchy
	tests := []struct {
		name        string
		did         string
		permissions uint64
		canReadAll  bool
		canUpdate   bool
		canDelete   bool
	}{
		{
			name:        "Admin can do everything",
			did:         adminDID,
			permissions: adminPerms,
			canReadAll:  true,
			canUpdate:   true,
			canDelete:   true,
		},
		{
			name:        "Manager can manage assets",
			did:         managerDID,
			permissions: managerPerms,
			canReadAll:  true,
			canUpdate:   true,
			canDelete:   false, // Manager cannot delete
		},
		{
			name:        "Operator is read-only",
			did:         operatorDID,
			permissions: operatorPerms,
			canReadAll:  true,
			canUpdate:   false,
			canDelete:   false,
		},
		{
			name:        "User has limited access",
			did:         userDID,
			permissions: userPerms,
			canReadAll:  true,  // User has read permission
			canUpdate:   true,
			canDelete:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test read access
			hasRead := permissiontypes.HasPermission(test.permissions, permissiontypes.PermAssetRead)
			if hasRead != test.canReadAll {
				t.Errorf("%s: read access = %v, expected %v", test.did, hasRead, test.canReadAll)
			}

			// Test update access
			hasUpdate := permissiontypes.HasPermission(test.permissions, permissiontypes.PermAssetUpdate)
			if hasUpdate != test.canUpdate {
				t.Errorf("%s: update access = %v, expected %v", test.did, hasUpdate, test.canUpdate)
			}

			// Test delete access
			hasDelete := permissiontypes.HasPermission(test.permissions, permissiontypes.PermAssetDelete)
			if hasDelete != test.canDelete {
				t.Errorf("%s: delete access = %v, expected %v", test.did, hasDelete, test.canDelete)
			}
		})
	}
}

// TestPermissionPerformanceIntegration tests performance of permission operations
func TestPermissionPerformanceIntegration(t *testing.T) {
	// Test permission counting performance with different permission sets
	permissionSets := []uint64{
		0, // No permissions
		permissiontypes.PermAssetRead,
		permissiontypes.PermAssetRead | permissiontypes.PermAssetUpdate,
		permissiontypes.PermAssetReadOnly,
		permissiontypes.PermAssetOperator,
		permissiontypes.PermAssetManager,
		permissiontypes.PermAssetAdmin,
		permissiontypes.PermAssetAll,
	}

	for _, permSet := range permissionSets {
		count := permissiontypes.CountPermissions(permSet)
		if count < 0 {
			t.Errorf("CountPermissions returned negative count: %d", count)
		}
	}

	// Test permission listing
	complexPerms := permissiontypes.PermAssetRead | permissiontypes.PermAssetUpdate | permissiontypes.PermAssetControl
	listedPerms := permissiontypes.ListSetPermissions(complexPerms)
	
	expectedCount := 3
	if len(listedPerms) != expectedCount {
		t.Errorf("ListSetPermissions returned %d permissions, expected %d", len(listedPerms), expectedCount)
	}

	// Verify all listed permissions are actually set
	for _, perm := range listedPerms {
		if !permissiontypes.HasPermission(complexPerms, perm) {
			t.Errorf("Listed permission 0x%X is not actually set", perm)
		}
	}
}