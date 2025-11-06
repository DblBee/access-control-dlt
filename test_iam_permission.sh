#!/bin/bash

# IAM and Permission System Test Runner
# This script executes the comprehensive test suite for IAM and Permission modules

set -e

echo "=== IAM and Permission System Test Suite ==="
echo "Starting comprehensive testing..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
PASSED=0
FAILED=0
SKIPPED=0

# Function to run a test and track results
run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -n "Testing $test_name... "
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        ((FAILED++))
        return 1
    fi
}

# Function to run a test with verbose output
run_test_verbose() {
    local test_name=$1
    local test_command=$2
    
    echo "=== Testing $test_name ==="
    
    if eval "$test_command"; then
        echo -e "${GREEN}✓ $test_name PASSED${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ $test_name FAILED${NC}"
        ((FAILED++))
        return 1
    fi
}

echo ""
echo "1. Running Permission System Tests..."
echo "====================================="

# Permission bit operations
run_test "Permission bit validation" "go test -v ./x/permission/types/ -run TestValidatePermissionBits"
run_test "Permission bit counting" "go test -v ./x/permission/types/ -run TestCountPermissions"
run_test "Permission bit listing" "go test -v ./x/permission/types/ -run TestListSetPermissions"

# Permission operations
run_test "Permission operations" "go test -v ./x/permission/types/ -run TestPermissionOperations"
run_test "Permission names and descriptions" "go test -v ./x/permission/types/ -run TestPermissionNames"

echo ""
echo "2. Running IAM System Tests..."
echo "==============================="

# IAM validation tests
run_test "IAM validation" "go test -v ./x/iam/types/ -run TestValidation"
run_test "DID document tests" "go test -v ./x/iam/types/ -run TestDIDDocument"
run_test "Credential tests" "go test -v ./x/iam/types/ -run TestCredential"

echo ""
echo "3. Running Integration Tests..."
echo "=============================="

# IAM-Permission integration
run_test_verbose "IAM Permission Integration" "go test -v ./x/ -run TestIAMPermissionIntegration"
run_test_verbose "Permission Role Integration" "go test -v ./x/ -run TestPermissionRoleIntegration"
run_test_verbose "Permission Time Integration" "go test -v ./x/ -run TestPermissionTimeIntegration"
run_test_verbose "Permission Boundary Integration" "go test -v ./x/ -run TestPermissionBoundaryIntegration"
run_test_verbose "Permission Complex Integration" "go test -v ./x/ -run TestPermissionComplexIntegration"
run_test_verbose "Permission Performance Integration" "go test -v ./x/ -run TestPermissionPerformanceIntegration"

echo ""
echo "4. Running Benchmark Tests..."
echo "=============================="

# Benchmarks
run_test "Permission benchmarks" "go test -bench=. ./x/permission/types/ -benchtime=1s"
run_test "IAM benchmarks" "go test -bench=. ./x/iam/types/ -benchtime=1s"

echo ""
echo "5. Running Coverage Analysis..."
echo "================================"

# Coverage
if command -v go tool cover >/dev/null 2>&1; then
    echo "Generating coverage report..."
    go test -coverprofile=coverage.out ./x/permission/types/ ./x/iam/types/ ./x/
    go tool cover -func=coverage.out | tail -10
    echo "Coverage report saved to coverage.out"
else
    echo -e "${YELLOW}Coverage tools not available, skipping coverage analysis${NC}"
    ((SKIPPED++))
fi

echo ""
echo "6. Security Validation..."
echo "========================="

# Security checks
run_test "Permission boundary validation" "go test -v ./x/permission/types/ -run TestValidatePermissionBits"
run_test "IAM validation security" "go test -v ./x/iam/types/ -run TestValidation"

echo ""
echo "=== Test Summary ==="
echo "==================="
echo -e "Tests Passed: ${GREEN}$PASSED${NC}"
echo -e "Tests Failed: ${RED}$FAILED${NC}"
echo -e "Tests Skipped: ${YELLOW}$SKIPPED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed successfully!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Please check the output above.${NC}"
    exit 1
fi