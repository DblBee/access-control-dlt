package keeper

import (
	"acmain/x/iam/types"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"sort"

	sdkerrors "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

// hashCredential creates a canonical hash of the credential for signing
// This must be deterministic - same credential produces same hash
func hashCredential(issuer, subject string, credType types.CredentialType, claims map[string]string, validFrom, validUntil int64) []byte {
	h := sha256.New()

	// Write fields in fixed order
	h.Write([]byte(issuer))
	h.Write([]byte(subject))

	// Write credential type as bytes
	credTypeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(credTypeBytes, uint32(credType))
	h.Write(credTypeBytes)

	// Sort claims keys for determinism
	if len(claims) > 0 {
		keys := make([]string, 0, len(claims))
		for k := range claims {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Write sorted claims
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte(claims[k]))
		}
	}

	// Write timestamps
	validFromBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(validFromBytes, uint64(validFrom))
	h.Write(validFromBytes)

	validUntilBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(validUntilBytes, uint64(validUntil))
	h.Write(validUntilBytes)

	return h.Sum(nil)
}

// verifySignature verifies a signature against a public key
func verifySignature(publicKey []byte, message []byte, signature []byte, keyType types.KeyType) error {
	switch keyType {
	case types.KEY_TYPE_ED25519:
		// Ed25519 public key should be 32 bytes
		if len(publicKey) != 32 {
			return sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid Ed25519 public key length")
		}

		// Ed25519 signature should be 64 bytes
		if len(signature) != 64 {
			return sdkerrors.Wrap(errors.ErrUnauthorized, "invalid Ed25519 signature length")
		}

		// Verify the signature
		if !ed25519.Verify(publicKey, message, signature) {
			return sdkerrors.Wrap(errors.ErrUnauthorized, "Ed25519 signature verification failed")
		}

		return nil

	case types.KEY_TYPE_SECP256K1:
		// secp256k1 public key should be 33 (compressed) or 65 (uncompressed) bytes
		if len(publicKey) != 33 && len(publicKey) != 65 {
			return sdkerrors.Wrap(errors.ErrInvalidRequest, "invalid secp256k1 public key length")
		}

		// Create a secp256k1 public key object
		pubKey := &secp256k1.PubKey{Key: publicKey}

		// Verify the signature
		if !pubKey.VerifySignature(message, signature) {
			return sdkerrors.Wrap(errors.ErrUnauthorized, "secp256k1 signature verification failed")
		}

		return nil

	default:
		return sdkerrors.Wrap(errors.ErrInvalidRequest, "unsupported key type for signature verification")
	}
}

// getProofType returns the W3C proof type string for a key type
func getProofType(keyType types.KeyType) string {
	switch keyType {
	case types.KEY_TYPE_ED25519:
		return "Ed25519Signature2020"
	case types.KEY_TYPE_SECP256K1:
		return "EcdsaSecp256k1Signature2019"
	case types.KEY_TYPE_RSA:
		return "RsaSignature2018"
	case types.KEY_TYPE_ECDSA:
		return "EcdsaSecp256r1Signature2019"
	default:
		return "UnknownSignature"
	}
}
