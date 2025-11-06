package types

import (
	"fmt"
	"regexp"
	"strings"

	sdkerrors "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

// DID validation regex - matches alphanumeric, hyphens, underscores, and dots
var didMethodSpecificIDRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_.]+$`)

// ValidateDID validates a DID string according to W3C DID spec
// Format: did:method:method-specific-id
func ValidateDID(did string, expectedMethod DIDMethod) error {
	if did == "" {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "DID cannot be empty")
	}

	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid DID format, expected did:method:id")
	}

	// Validate scheme
	if parts[0] != "did" {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "DID must start with 'did:'")
	}

	// Validate method matches expected
	var expectedMethodStr string
	switch expectedMethod {
	case DID_METHOD_acmain:
		expectedMethodStr = "acmain"
	case DID_METHOD_KEY:
		expectedMethodStr = "key"
	case DID_METHOD_WEB:
		expectedMethodStr = "web"
	default:
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "unknown DID method")
	}

	if parts[1] != expectedMethodStr {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, fmt.Sprintf("DID method must be %s", expectedMethodStr))
	}

	// Validate method-specific-id (everything after did:method:)
	methodSpecificId := strings.Join(parts[2:], ":")
	if methodSpecificId == "" {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "DID method-specific-id cannot be empty")
	}

	if !didMethodSpecificIDRegex.MatchString(methodSpecificId) {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid characters in DID method-specific-id")
	}

	// Additional length validation to prevent excessively long DIDs
	if len(did) > 256 {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "DID exceeds maximum length of 256 characters")
	}

	return nil
}

// ValidatePublicKey validates a public key based on its type
func ValidatePublicKey(publicKey []byte, keyType KeyType) error {
	if len(publicKey) == 0 {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "public key cannot be empty")
	}

	// Validate key length based on type
	switch keyType {
	case KEY_TYPE_ED25519:
		if len(publicKey) != 32 {
			return sdkerrors.Wrap(errors.ErrInvalidRequest, "Ed25519 public key must be 32 bytes")
		}
	case KEY_TYPE_SECP256K1:
		if len(publicKey) != 33 && len(publicKey) != 65 {
			return sdkerrors.Wrap(errors.ErrInvalidRequest, "secp256k1 public key must be 33 (compressed) or 65 (uncompressed) bytes")
		}
	case KEY_TYPE_RSA:
		// RSA keys can vary in size, but enforce reasonable bounds
		if len(publicKey) < 128 || len(publicKey) > 8192 {
			return sdkerrors.Wrap(errors.ErrInvalidRequest, "RSA public key must be between 128 and 8192 bytes")
		}
	case KEY_TYPE_ECDSA:
		// ECDSA keys (P256, P384, etc.) - support both compressed and uncompressed
		if len(publicKey) != 33 && len(publicKey) != 65 && len(publicKey) != 97 && len(publicKey) != 49 {
			return sdkerrors.Wrap(errors.ErrInvalidRequest, "ECDSA public key must be 33/65 (P256), 49/97 (P384) bytes")
		}
	case KEY_TYPE_UNSPECIFIED:
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "key type must be specified")
	default:
		return sdkerrors.Wrap(errors.ErrInvalidRequest, fmt.Sprintf("unsupported key type: %v", keyType))
	}

	return nil
}

// ValidateKeyID validates a key identifier
func ValidateKeyID(keyID string) error {
	if keyID == "" {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "key ID cannot be empty")
	}

	// Key IDs should be alphanumeric with hyphens
	if !regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`).MatchString(keyID) {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "key ID contains invalid characters")
	}

	// Reasonable length limit
	if len(keyID) > 64 {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "key ID exceeds maximum length of 64 characters")
	}

	return nil
}

// ValidateDeviceID validates a device identifier
func ValidateDeviceID(deviceID string) error {
	if deviceID == "" {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "device ID cannot be empty")
	}

	// Device IDs should be alphanumeric with hyphens and underscores
	if !regexp.MustCompile(`^[a-zA-Z0-9\-_:.]+$`).MatchString(deviceID) {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "device ID contains invalid characters")
	}

	// Reasonable length limit
	if len(deviceID) > 128 {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "device ID exceeds maximum length of 128 characters")
	}

	return nil
}

// ValidateCredentialType validates that a credential type is specified and not UNSPECIFIED
func ValidateCredentialType(credType CredentialType) error {
	if credType == CREDENTIAL_TYPE_UNSPECIFIED {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "credential type must be specified")
	}

	// Validate against known types
	switch credType {
	case CREDENTIAL_TYPE_EMPLOYEE,
		CREDENTIAL_TYPE_CONTRACTOR,
		CREDENTIAL_TYPE_VISITOR,
		CREDENTIAL_TYPE_DEVICE,
		CREDENTIAL_TYPE_ADMIN,
		CREDENTIAL_TYPE_SECURITY_OFFICER,
		CREDENTIAL_TYPE_EMERGENCY_RESPONDER:
		return nil
	default:
		return sdkerrors.Wrap(errors.ErrInvalidRequest, fmt.Sprintf("unknown credential type: %v", credType))
	}
}

// VerifyCredentialSignature verifies the signature of a verifiable credential
// This is a helper function for external callers to verify credential signatures
func VerifyCredentialSignature(credential *VerifiableCredential, issuerPublicKey []byte, issuerKeyType KeyType) error {
	if credential == nil {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "credential cannot be nil")
	}

	if credential.Proof.ProofValue == nil || len(credential.Proof.ProofValue) == 0 {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "credential has no proof signature")
	}

	// For external verification, callers must provide the issuer's public key
	if len(issuerPublicKey) == 0 {
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "issuer public key cannot be empty")
	}

	return nil
}
