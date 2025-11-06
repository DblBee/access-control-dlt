package types

import (
	"testing"
)

func TestHasPermission(t *testing.T) {
	tests := []struct {
		name               string
		permissionBits     uint64
		requiredPermission uint64
		expected           bool
	}{
		{
			name:               "has single permission",
			permissionBits:     PermAssetRead,
			requiredPermission: PermAssetRead,
			expected:           true,
		},
		{
			name:               "does not have permission",
			permissionBits:     PermAssetRead,
			requiredPermission: PermAssetUpdate,
			expected:           false,
		},
		{
			name:               "has combined permissions",
			permissionBits:     PermAssetRead | PermAssetUpdate,
			requiredPermission: PermAssetRead,
			expected:           true,
		},
		{
			name:               "has all required permissions",
			permissionBits:     PermAssetRead | PermAssetUpdate | PermAssetControl,
			requiredPermission: PermAssetRead | PermAssetUpdate,
			expected:           true,
		},
		{
			name:               "missing one of multiple required permissions",
			permissionBits:     PermAssetRead,
			requiredPermission: PermAssetRead | PermAssetUpdate,
			expected:           false,
		},
		{
			name:               "empty permissions",
			permissionBits:     0,
			requiredPermission: PermAssetRead,
			expected:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasPermission(tt.permissionBits, tt.requiredPermission)
			if result != tt.expected {
				t.Errorf("HasPermission() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestHasAnyPermission(t *testing.T) {
	tests := []struct {
		name                string
		permissionBits      uint64
		requiredPermissions uint64
		expected            bool
	}{
		{
			name:                "has one of multiple permissions",
			permissionBits:      PermAssetRead,
			requiredPermissions: PermAssetRead | PermAssetUpdate,
			expected:            true,
		},
		{
			name:                "has all permissions",
			permissionBits:      PermAssetRead | PermAssetUpdate,
			requiredPermissions: PermAssetRead | PermAssetUpdate,
			expected:            true,
		},
		{
			name:                "has none of the permissions",
			permissionBits:      PermAssetControl,
			requiredPermissions: PermAssetRead | PermAssetUpdate,
			expected:            false,
		},
		{
			name:                "empty permission set",
			permissionBits:      0,
			requiredPermissions: PermAssetRead,
			expected:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAnyPermission(tt.permissionBits, tt.requiredPermissions)
			if result != tt.expected {
				t.Errorf("HasAnyPermission() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestHasAllPermissions(t *testing.T) {
	tests := []struct {
		name                string
		permissionBits      uint64
		requiredPermissions uint64
		expected            bool
	}{
		{
			name:                "has all required permissions",
			permissionBits:      PermAssetRead | PermAssetUpdate | PermAssetControl,
			requiredPermissions: PermAssetRead | PermAssetUpdate,
			expected:            true,
		},
		{
			name:                "missing one permission",
			permissionBits:      PermAssetRead,
			requiredPermissions: PermAssetRead | PermAssetUpdate,
			expected:            false,
		},
		{
			name:                "exact match",
			permissionBits:      PermAssetRead | PermAssetUpdate,
			requiredPermissions: PermAssetRead | PermAssetUpdate,
			expected:            true,
		},
		{
			name:                "empty required permissions",
			permissionBits:      PermAssetRead,
			requiredPermissions: 0,
			expected:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAllPermissions(tt.permissionBits, tt.requiredPermissions)
			if result != tt.expected {
				t.Errorf("HasAllPermissions() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestAddPermission(t *testing.T) {
	tests := []struct {
		name     string
		initial  uint64
		toAdd    uint64
		expected uint64
	}{
		{
			name:     "add single permission to empty set",
			initial:  0,
			toAdd:    PermAssetRead,
			expected: PermAssetRead,
		},
		{
			name:     "add permission to existing set",
			initial:  PermAssetRead,
			toAdd:    PermAssetUpdate,
			expected: PermAssetRead | PermAssetUpdate,
		},
		{
			name:     "add already existing permission (idempotent)",
			initial:  PermAssetRead,
			toAdd:    PermAssetRead,
			expected: PermAssetRead,
		},
		{
			name:     "add multiple permissions",
			initial:  PermAssetRead,
			toAdd:    PermAssetUpdate | PermAssetControl,
			expected: PermAssetRead | PermAssetUpdate | PermAssetControl,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AddPermission(tt.initial, tt.toAdd)
			if result != tt.expected {
				t.Errorf("AddPermission() = 0x%X, expected 0x%X", result, tt.expected)
			}
		})
	}
}

func TestRemovePermission(t *testing.T) {
	tests := []struct {
		name     string
		initial  uint64
		toRemove uint64
		expected uint64
	}{
		{
			name:     "remove single permission",
			initial:  PermAssetRead | PermAssetUpdate,
			toRemove: PermAssetRead,
			expected: PermAssetUpdate,
		},
		{
			name:     "remove non-existent permission (no-op)",
			initial:  PermAssetRead,
			toRemove: PermAssetUpdate,
			expected: PermAssetRead,
		},
		{
			name:     "remove all permissions",
			initial:  PermAssetRead | PermAssetUpdate,
			toRemove: PermAssetRead | PermAssetUpdate,
			expected: 0,
		},
		{
			name:     "remove from empty set (no-op)",
			initial:  0,
			toRemove: PermAssetRead,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemovePermission(tt.initial, tt.toRemove)
			if result != tt.expected {
				t.Errorf("RemovePermission() = 0x%X, expected 0x%X", result, tt.expected)
			}
		})
	}
}

func TestCombinePermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []uint64
		expected    uint64
	}{
		{
			name:        "combine two permissions",
			permissions: []uint64{PermAssetRead, PermAssetUpdate},
			expected:    PermAssetRead | PermAssetUpdate,
		},
		{
			name:        "combine multiple permissions",
			permissions: []uint64{PermAssetRead, PermAssetUpdate, PermAssetControl},
			expected:    PermAssetRead | PermAssetUpdate | PermAssetControl,
		},
		{
			name:        "combine with overlaps",
			permissions: []uint64{PermAssetRead | PermAssetUpdate, PermAssetUpdate | PermAssetControl},
			expected:    PermAssetRead | PermAssetUpdate | PermAssetControl,
		},
		{
			name:        "combine empty list",
			permissions: []uint64{},
			expected:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CombinePermissions(tt.permissions...)
			if result != tt.expected {
				t.Errorf("CombinePermissions() = 0x%X, expected 0x%X", result, tt.expected)
			}
		})
	}
}

func TestIntersectPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []uint64
		expected    uint64
	}{
		{
			name:        "intersect with common permissions",
			permissions: []uint64{PermAssetRead | PermAssetUpdate, PermAssetRead | PermAssetControl},
			expected:    PermAssetRead,
		},
		{
			name:        "intersect with no common permissions",
			permissions: []uint64{PermAssetRead, PermAssetUpdate},
			expected:    0,
		},
		{
			name:        "intersect identical sets",
			permissions: []uint64{PermAssetRead | PermAssetUpdate, PermAssetRead | PermAssetUpdate},
			expected:    PermAssetRead | PermAssetUpdate,
		},
		{
			name:        "intersect empty list",
			permissions: []uint64{},
			expected:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IntersectPermissions(tt.permissions...)
			if result != tt.expected {
				t.Errorf("IntersectPermissions() = 0x%X, expected 0x%X", result, tt.expected)
			}
		})
	}
}

func TestCountPermissions(t *testing.T) {
	tests := []struct {
		name           string
		permissionBits uint64
		expected       int
	}{
		{
			name:           "single permission",
			permissionBits: PermAssetRead,
			expected:       1,
		},
		{
			name:           "multiple permissions",
			permissionBits: PermAssetRead | PermAssetUpdate | PermAssetControl,
			expected:       3,
		},
		{
			name:           "no permissions",
			permissionBits: 0,
			expected:       0,
		},
		{
			name:           "many permissions",
			permissionBits: PermAssetReadOnly,
			expected:       3, // Read, Audit, Monitor
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CountPermissions(tt.permissionBits)
			if result != tt.expected {
				t.Errorf("CountPermissions() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestListSetPermissions(t *testing.T) {
	tests := []struct {
		name           string
		permissionBits uint64
		expectedCount  int
	}{
		{
			name:           "single permission",
			permissionBits: PermAssetRead,
			expectedCount:  1,
		},
		{
			name:           "multiple permissions",
			permissionBits: PermAssetRead | PermAssetUpdate | PermAssetControl,
			expectedCount:  3,
		},
		{
			name:           "no permissions",
			permissionBits: 0,
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ListSetPermissions(tt.permissionBits)
			if len(result) != tt.expectedCount {
				t.Errorf("ListSetPermissions() returned %d permissions, expected %d", len(result), tt.expectedCount)
			}

			// Verify each listed permission is actually set
			for _, perm := range result {
				if !HasPermission(tt.permissionBits, perm) {
					t.Errorf("ListSetPermissions() returned permission 0x%X which is not set", perm)
				}
			}
		})
	}
}

func TestGetPermissionName(t *testing.T) {
	tests := []struct {
		name          string
		permissionBit uint64
		expected      string
	}{
		{
			name:          "asset read",
			permissionBit: PermAssetRead,
			expected:      "asset.read",
		},
		{
			name:          "did update",
			permissionBit: PermDIDUpdate,
			expected:      "did.update",
		},
		{
			name:          "credential issue",
			permissionBit: PermCredentialIssue,
			expected:      "credential.issue",
		},
		{
			name:          "unknown permission",
			permissionBit: 1 << 63,
			expected:      "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPermissionName(tt.permissionBit)
			if result != tt.expected {
				t.Errorf("GetPermissionName() = %s, expected %s", result, tt.expected)
			}
		})
	}
}

func TestGetPermissionsByResourceType(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		expected     uint64
	}{
		{
			name:         "asset permissions",
			resourceType: ResourceTypeAsset,
			expected:     PermAssetAll,
		},
		{
			name:         "did permissions",
			resourceType: ResourceTypeDID,
			expected:     PermDIDAll,
		},
		{
			name:         "credential permissions",
			resourceType: ResourceTypeCredential,
			expected:     PermCredentialAll,
		},
		{
			name:         "device permissions",
			resourceType: ResourceTypeDevice,
			expected:     PermDeviceAll,
		},
		{
			name:         "unknown resource type",
			resourceType: "unknown",
			expected:     PermNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPermissionsByResourceType(tt.resourceType)
			if result != tt.expected {
				t.Errorf("GetPermissionsByResourceType() = 0x%X, expected 0x%X", result, tt.expected)
			}
		})
	}
}

func TestValidatePermissionBits(t *testing.T) {
	tests := []struct {
		name           string
		resourceType   string
		permissionBits uint64
		expected       bool
	}{
		{
			name:           "valid asset permissions",
			resourceType:   ResourceTypeAsset,
			permissionBits: PermAssetRead | PermAssetUpdate,
			expected:       true,
		},
		{
			name:           "invalid asset permissions (DID bit)",
			resourceType:   ResourceTypeAsset,
			permissionBits: PermAssetRead | PermDIDRead,
			expected:       false,
		},
		{
			name:           "valid DID permissions",
			resourceType:   ResourceTypeDID,
			permissionBits: PermDIDRead | PermDIDUpdate,
			expected:       true,
		},
		{
			name:           "system permissions allow all",
			resourceType:   ResourceTypeSystem,
			permissionBits: PermAssetRead | PermDIDRead | PermCredentialRead,
			expected:       true,
		},
		{
			name:           "empty permissions",
			resourceType:   ResourceTypeAsset,
			permissionBits: 0,
			expected:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePermissionBits(tt.resourceType, tt.permissionBits)
			if result != tt.expected {
				t.Errorf("ValidatePermissionBits() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestPermissionMasks(t *testing.T) {
	tests := []struct {
		name          string
		mask          uint64
		shouldHave    []uint64
		shouldNotHave []uint64
	}{
		{
			name: "asset read only",
			mask: PermAssetReadOnly,
			shouldHave: []uint64{
				PermAssetRead,
				PermAssetAudit,
				PermAssetMonitor,
			},
			shouldNotHave: []uint64{
				PermAssetUpdate,
				PermAssetDelete,
				PermAssetControl,
			},
		},
		{
			name: "asset operator",
			mask: PermAssetOperator,
			shouldHave: []uint64{
				PermAssetRead,
				PermAssetAudit,
				PermAssetMonitor,
				PermAssetControl,
			},
			shouldNotHave: []uint64{
				PermAssetUpdate,
				PermAssetDelete,
			},
		},
		{
			name: "asset manager",
			mask: PermAssetManager,
			shouldHave: []uint64{
				PermAssetRead,
				PermAssetUpdate,
				PermAssetControl,
				PermAssetConfig,
				PermAssetMaintain,
			},
			shouldNotHave: []uint64{
				PermAssetDelete,
				PermAssetCreate,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, perm := range tt.shouldHave {
				if !HasPermission(tt.mask, perm) {
					t.Errorf("Mask 0x%X should have permission 0x%X (%s)", tt.mask, perm, GetPermissionName(perm))
				}
			}

			for _, perm := range tt.shouldNotHave {
				if HasPermission(tt.mask, perm) {
					t.Errorf("Mask 0x%X should not have permission 0x%X (%s)", tt.mask, perm, GetPermissionName(perm))
				}
			}
		})
	}
}

func BenchmarkHasPermission(b *testing.B) {
	permissionBits := PermAssetRead | PermAssetUpdate | PermAssetControl
	requiredPermission := PermAssetUpdate

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasPermission(permissionBits, requiredPermission)
	}
}

func BenchmarkAddPermission(b *testing.B) {
	permissionBits := PermAssetRead

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AddPermission(permissionBits, PermAssetUpdate)
	}
}

func BenchmarkCountPermissions(b *testing.B) {
	permissionBits := PermAssetReadOnly | PermAssetOperator

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CountPermissions(permissionBits)
	}
}
