package types

import (
	"fmt"
)

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Params:               DefaultParams(),
		DidDocuments:         []DIDDocument{},
		Credentials:          []VerifiableCredential{},
		RevokedCredentialIds: []string{},
		DeviceKeys:           []DeviceKey{},
	}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	// Validate params
	if err := gs.Params.Validate(); err != nil {
		return err
	}

	// Validate DID documents
	didSet := make(map[string]bool)
	for _, doc := range gs.DidDocuments {
		if doc.Id == "" {
			return fmt.Errorf("DID document has empty ID")
		}
		if didSet[doc.Id] {
			return fmt.Errorf("duplicate DID: %s", doc.Id)
		}
		didSet[doc.Id] = true
	}

	// Validate credentials
	credSet := make(map[string]bool)
	for _, cred := range gs.Credentials {
		if cred.Id == "" {
			return fmt.Errorf("credential has empty ID")
		}
		if credSet[cred.Id] {
			return fmt.Errorf("duplicate credential ID: %s", cred.Id)
		}
		credSet[cred.Id] = true
	}

	// Validate revoked credential IDs
	for _, id := range gs.RevokedCredentialIds {
		if id == "" {
			return fmt.Errorf("revoked credential ID cannot be empty")
		}
	}

	// Validate device keys
	deviceSet := make(map[string]bool)
	for _, dk := range gs.DeviceKeys {
		if dk.DeviceId == "" {
			return fmt.Errorf("device key has empty device ID")
		}
		if deviceSet[dk.DeviceId] {
			return fmt.Errorf("duplicate device ID: %s", dk.DeviceId)
		}
		deviceSet[dk.DeviceId] = true
	}

	return nil
}
