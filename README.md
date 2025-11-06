# Access Control Distributed Ledger

This project uses the [Ignite CLI](https://docs.ignite.com/) to generate the boilerplate code for the custom permissioned private cosmos blockchain.

## Scaffolding

[Ignite Scaffolding](https://docs.ignite.com/CLI-Commands/cli-commands#ignite-scaffold) is how the Ignite CLI generates code. This guide will show you the scaffolding commands needed to create this blockchain locally. 

## Create a new blockchain

```sh
ignite s chain acmain
```

## Asset Management Module

```sh
ignite s module assetmgmt
```

### AssetType, AssetState

Create an `proto/acmain/assetmgmt/v1/enums.proto` file and add the enums

```proto
syntax = "proto3";
package acmain.assetmgmt.v1;

import "gogoproto/gogo.proto";

option go_package = "acmain/x/assetmgmt/types";

// AssetType defines the enum of supported physical asset types.
enum AssetType {
  // does not set the enum prefix in generated code
  option (gogoproto.goproto_enum_prefix) = false;
  // ASSET_TYPE_UNSPECIFIED represents an unspecified asset type
  ASSET_TYPE_UNSPECIFIED = 0;
  // ASSET_TYPE_DOOR represents a physical door asset
  ASSET_TYPE_DOOR = 1;
  // ASSET_TYPE_GATE represents a physical gate asset
  ASSET_TYPE_GATE = 2;
  // ASSET_TYPE_BARRIER represents a physical barrier asset
  ASSET_TYPE_BARRIER = 3;
  // ASSET_TYPE_ELEVATOR represents an elevator asset
  ASSET_TYPE_ELEVATOR = 4;
  // ASSET_TYPE_TURNSTILE represents a turnstile asset
  ASSET_TYPE_TURNSTILE = 5;
}

// AssetState defines the enum of supported asset operational states.
enum AssetState {
  // does not set the enum prefix in generated code
  option (gogoproto.goproto_enum_prefix) = false;
  // ASSET_STATE_UNSPECIFIED represents an unspecified state
  ASSET_STATE_UNSPECIFIED = 0;
  // ASSET_STATE_LOCKED represents a locked asset
  ASSET_STATE_LOCKED = 1;
  // ASSET_STATE_UNLOCKED represents an unlocked asset
  ASSET_STATE_UNLOCKED = 2;
  // ASSET_STATE_OPEN represents an open asset
  ASSET_STATE_OPEN = 3;
  // ASSET_STATE_CLOSED represents a closed asset
  ASSET_STATE_CLOSED = 4;
  // ASSET_STATE_MAINTENANCE represents an asset in maintenance
  ASSET_STATE_MAINTENANCE = 5;
  // ASSET_STATE_OFFLINE represents an offline asset
  ASSET_STATE_OFFLINE = 6;
  // ASSET_STATE_DEACTIVATED represents a deactivated asset
  ASSET_STATE_DEACTIVATED = 7;
}

```

### LocationInfo

```sh
ignite s type LocationInfo BuildingId FloorId ZoneId Latitude Longitude --module assetmgmt
```

Add the updated proto properties for the Equal message

```proto
syntax = "proto3";
package acmain.assetmgmt.v1;

import "gogoproto/gogo.proto";

option go_package = "acmain/x/assetmgmt/types";

// LocationInfo encodes the physical location of an asset with building,
// floor, and zone identifiers. This serves as the primary location binding
// for location-based access control policies.
message LocationInfo {
  // adds the Equal function to this proto buff
  // https://pkg.go.dev/github.com/gogo/protobuf/plugin/equal
  option (gogoproto.equal) = true;

  // building_id is the unique identifier for the building/facility.
  // This is the primary location scope identifier.
  string building_id = 1;

  // floor_id is the unique identifier for the floor within the building.
  string floor_id = 2;

  // zone_id is the unique identifier for the zone/area on the floor.
  string zone_id = 3;

  // latitude is the optional GPS latitude coordinate of the asset.
  double latitude = 4;

  // longitude is the optional GPS longitude coordinate of the asset.
  double longitude = 5;
}
```

### Asset

```sh
ignite s type Asset AssetId AssetType Name Description Location ControllerAddress State CreatedAt UpdatedAt --module assetmgmt
```

Update the AssetType, Location, and State properties with the types in the asset.proto file

```proto
syntax = "proto3";
package acmain.assetmgmt.v1;

import "acmain/assetmgmt/v1/enums.proto";
import "acmain/assetmgmt/v1/location_info.proto";
import "amino/amino.proto";
import "cosmos_proto/cosmos.proto";
import "gogoproto/gogo.proto";
import "google/protobuf/timestamp.proto";

option go_package = "acmain/x/assetmgmt/types";

// Asset defines the Asset message.
message Asset {
  // adds the Equal function to this proto buff
  // https://pkg.go.dev/github.com/gogo/protobuf/plugin/equal
  option (gogoproto.equal) = true;

  // provides a standardized identifier for the message type
  option (amino.name) = "acmain/x/assetmgmt/Asset";

  // asset_id is the unique identifier for this asset within the system.
  // Immutable after creation.
  string asset_id = 1;

  // asset_type specifies the type of physical asset (door, gate, barrier, etc).
  AssetType asset_type = 2;

  // name is a human-readable name for the asset.
  string name = 3;

  // description is an optional human-readable description of the asset.
  string description = 4;

  // location contains the immutable location binding for this asset.
  // Assets are location-scoped: an asset from Building A cannot be used
  // to grant access in Building B. This is enforced at network and app level.
  LocationInfo location = 5 [
    (gogoproto.nullable) = false,
    (amino.dont_omitempty) = true
  ];

  // controller_address is the Cosmos address of the entity that controls
  // this asset. Only the controller can update asset state and modify ACLs.
  // Typically the organization/facility manager.
  string controller_address = 6 [(cosmos_proto.scalar) = "cosmos.AddressString"];

  // state is the current operational state of the asset.
  // Updated via MsgUpdateAssetState transactions.
  AssetState state = 7;

  // metadata is optional key-value data for asset-specific attributes.
  // Examples: model_number, serial_number, manufacturer, firmware_version, etc.
  // Maps are used to support arbitrary metadata without schema changes.
  map<string, string> metadata = 8;

  // created_at is the block timestamp when this asset was created.
  // Immutable after creation.
  google.protobuf.Timestamp created_at = 9 [
    (gogoproto.nullable) = false,
    (gogoproto.stdtime) = true,
    (amino.dont_omitempty) = true
  ];

  // updated_at is the block timestamp of the most recent state update.
  // Updated whenever asset state changes or metadata is modified.
  google.protobuf.Timestamp updated_at = 10 [
    (gogoproto.nullable) = false,
    (gogoproto.stdtime) = true,
    (amino.dont_omitempty) = true
  ];
}

```

### Queries

#### Asset

```sh
ignite s query Asset AssetId --module assetmgmt
```

#### AssetsByLocation

```sh
ignite s query AssetsByLocation BuildingId FloorId ZoneId Pagination --module assetmgmt
```

#### AssetsByType

```sh
ignite s query AssetsByType AssetType BuildingId Pagination --module assetmgmt
```

#### AssetsByController

```sh
ignite s query AssetsByController ControllerAddress BuildingId Pagination --module assetmgmt
 ```

#### AssetsByState

```sh
ignite s query AssetsByState State BuildingId Pagination --module assetmgmt
 ```


## IAM Module

```sh
ignite s module iam
```

### CredentialType, CredentialStatus, KeyType, DIDMethod

Create an `proto/acmain/iam/v1/enums.proto` file and add the enums

```proto
syntax = "proto3";
package acmain.iam.v1;

import "gogoproto/gogo.proto";

option go_package = "acmain/x/iam/types";

// CredentialType defines the type of verifiable credential
enum CredentialType {
  option (gogoproto.goproto_enum_prefix) = false;

  CREDENTIAL_TYPE_UNSPECIFIED = 0;
  CREDENTIAL_TYPE_EMPLOYEE = 1;
  CREDENTIAL_TYPE_CONTRACTOR = 2;
  CREDENTIAL_TYPE_VISITOR = 3;
  CREDENTIAL_TYPE_DEVICE = 4;
  CREDENTIAL_TYPE_ADMIN = 5;
  CREDENTIAL_TYPE_SECURITY_OFFICER = 6;
  CREDENTIAL_TYPE_EMERGENCY_RESPONDER = 7;
}

// CredentialStatus defines the status of a verifiable credential
enum CredentialStatus {
  option (gogoproto.goproto_enum_prefix) = false;

  CREDENTIAL_STATUS_UNSPECIFIED = 0;
  CREDENTIAL_STATUS_ACTIVE = 1;
  CREDENTIAL_STATUS_REVOKED = 2;
  CREDENTIAL_STATUS_EXPIRED = 3;
  CREDENTIAL_STATUS_SUSPENDED = 4;
}

// KeyType defines the cryptographic key type
enum KeyType {
  option (gogoproto.goproto_enum_prefix) = false;

  KEY_TYPE_UNSPECIFIED = 0;
  KEY_TYPE_ED25519 = 1;
  KEY_TYPE_SECP256K1 = 2;
  KEY_TYPE_RSA = 3;
  KEY_TYPE_ECDSA = 4;
}

// DIDMethod defines the DID method type
enum DIDMethod {
  option (gogoproto.goproto_enum_prefix) = false;

  DID_METHOD_UNSPECIFIED = 0;
  DID_METHOD_acmain = 1;         // acmain: method - primary method for this system
  DID_METHOD_KEY = 2;            // did:key: method - lightweight, no registry required
  DID_METHOD_WEB = 3;            // did:web: method - web-based DID resolution
}
```

### PublicKeyInfo

```sh
ignite s type PublicKeyInfo KeyId PublicKey KeyType Purpose Controller CreatedAt RevokedAt --module iam
```

Update the public_key to bytes type and key_type to KeyType enum

```proto
syntax = "proto3";
package acmain.iam.v1;

import "acmain/iam/v1/enums.proto";
import "amino/amino.proto";
import "gogoproto/gogo.proto";
import "google/protobuf/timestamp.proto";

option go_package = "acmain/x/iam/types";

// PublicKeyInfo defines the PublicKeyInfo message.
message PublicKeyInfo {
  option (amino.name) = "acmain/x/iam/PublicKeyInfo";

  // key_id is a unique identifier for the key within the DID document
  string key_id = 1;

  // public_key is the raw public key bytes
  bytes public_key = 2;

  // key_type specifies the cryptographic algorithm
  KeyType key_type = 3;

  // purpose describes the key's purpose (e.g., "authentication", "assertionMethod")
  string purpose = 4;

  // controller is the DID that controls this key (can differ from subject)
  string controller = 5;

  // created_at is the block timestamp when the key was added
  google.protobuf.Timestamp created_at = 6 [
    (gogoproto.stdtime) = true,
    (gogoproto.nullable) = false,
    (amino.dont_omitempty) = true
  ];

  // revoked_at is the block timestamp when the key was revoked (null if active)
  google.protobuf.Timestamp revoked_at = 7 [(gogoproto.stdtime) = true];
}
```

### VerificationRelationship

```sh
ignite s type VerificationRelationship RelationshipType KeyId --module iam
```

```proto
syntax = "proto3";
package acmain.iam.v1;

import "amino/amino.proto";

option go_package = "acmain/x/iam/types";

// VerificationRelationship represents a verification relationship in DID document
message VerificationRelationship {
  option (amino.name) = "acmain/x/iam/VerificationRelationship";

  // relationship_type describes the relationship (e.g., "authentication", "assertionMethod", "keyAgreement")
  string relationship_type = 1;

  // key_id references a key in the DID document
  string key_id = 2;
}
```

### ServiceEndpoint

```sh
ignite s type ServiceEndpoint Id Type ServiceEndpoint Description --module iam
```

```proto
syntax = "proto3";
package acmain.iam.v1;

import "amino/amino.proto";

option go_package = "acmain/x/iam/types";

// ServiceEndpoint represents a service endpoint in a DID document
message ServiceEndpoint {
  option (amino.name) = "acmain/x/iam/ServiceEndpoint";

  // id is the unique identifier for the service endpoint
  string id = 1;

  // type describes the service type (e.g., "VerifiableCredentialService", "WebAPI")
  string type = 2;

  // service_endpoint is the URL or endpoint address
  string service_endpoint = 3;

  // description provides additional context about the service
  string description = 4;
}
```

### DIDDocument

```sh
ignite s type DIDDocument Id Context Controller PublicKeys VerificationRelationships ServiceEndpoints AlsoKnownAs CreatedAt UpdatedAt Deactivated DeactivatedAt DIDMethod --module iam
```

Update the types to match the W3C DID specification

```proto
syntax = "proto3";
package acmain.iam.v1;

import "acmain/iam/v1/enums.proto";
import "acmain/iam/v1/public_key_info.proto";
import "acmain/iam/v1/service_endpoint.proto";
import "acmain/iam/v1/verification_relationship.proto";
import "amino/amino.proto";
import "gogoproto/gogo.proto";
import "google/protobuf/timestamp.proto";

option go_package = "acmain/x/iam/types";

// DIDDocument represents a W3C-compliant Decentralized Identifier Document
message DIDDocument {
  option (gogoproto.equal) = true;
  option (amino.name) = "acmain/x/iam/DIDDocument";

  // id is the DID (e.g., "did:acmain:cosmos1abcdef...")
  string id = 1;

  // context is the JSON-LD context
  repeated string context = 2;

  // controller is the Cosmos address that can update this DID
  string controller = 3;

  // public_keys contains all associated public keys
  repeated PublicKeyInfo public_keys = 4 [(gogoproto.nullable) = false];

  // verification_relationships defines how keys are used
  repeated VerificationRelationship verification_relationships = 5 [(gogoproto.nullable) = false];

  // service_endpoints contains external services
  repeated ServiceEndpoint service_endpoints = 6 [(gogoproto.nullable) = false];

  // also_known_as contains alternative identifiers
  repeated string also_known_as = 7;

  // created_at is the block timestamp of creation
  google.protobuf.Timestamp created_at = 8 [
    (gogoproto.nullable) = false,
    (gogoproto.stdtime) = true,
    (amino.dont_omitempty) = true
  ];

  // updated_at is the block timestamp of last update
  google.protobuf.Timestamp updated_at = 9 [
    (gogoproto.nullable) = false,
    (gogoproto.stdtime) = true,
    (amino.dont_omitempty) = true
  ];

  // deactivated indicates if the DID is deactivated
  bool deactivated = 10;

  // deactivated_at is the block timestamp when deactivated
  google.protobuf.Timestamp deactivated_at = 11 [(gogoproto.stdtime) = true];

  // did_method specifies the DID method used
  DIDMethod did_method = 12;
}
```

### CredentialSubject

```sh
ignite s type CredentialSubject Id Claims --module iam
```

Update Claims to be a map type

```proto
syntax = "proto3";
package acmain.iam.v1;

import "amino/amino.proto";

option go_package = "acmain/x/iam/types";

// CredentialSubject represents the subject of a verifiable credential
message CredentialSubject {
  option (amino.name) = "acmain/x/iam/CredentialSubject";

  // id is the DID of the subject
  string id = 1;

  // claims contains key-value attribute pairs (role, department, etc.)
  map<string, string> claims = 2;
}
```

### CredentialProof

```sh
ignite s type CredentialProof Type CreatedAt VerificationMethod ProofValue --module iam
```

Update ProofValue to bytes type

```proto
syntax = "proto3";
package acmain.iam.v1;

import "amino/amino.proto";
import "gogoproto/gogo.proto";
import "google/protobuf/timestamp.proto";

option go_package = "acmain/x/iam/types";

// CredentialProof represents a cryptographic proof for a verifiable credential
message CredentialProof {
  option (amino.name) = "acmain/x/iam/CredentialProof";

  // type is the proof type (e.g., "Ed25519Signature2020")
  string type = 1;

  // created_at is when the proof was created
  google.protobuf.Timestamp created_at = 2 [
    (gogoproto.stdtime) = true,
    (gogoproto.nullable) = false,
    (amino.dont_omitempty) = true
  ];

  // verification_method is the DID method used to verify (e.g., "#key-1")
  string verification_method = 3;

  // proof_value contains the signature bytes
  bytes proof_value = 4;
}
```

### CredentialStatusInfo

```sh
ignite s type CredentialStatusInfo Status UpdatedAt RevocationReason --module iam
```

Update Status to CredentialStatus enum type

```proto
syntax = "proto3";
package acmain.iam.v1;

import "acmain/iam/v1/enums.proto";
import "amino/amino.proto";
import "gogoproto/gogo.proto";
import "google/protobuf/timestamp.proto";

option go_package = "acmain/x/iam/types";

// CredentialStatusInfo tracks the status of a verifiable credential
message CredentialStatusInfo {
  option (amino.name) = "acmain/x/iam/CredentialStatusInfo";

  // status is the current credential status
  CredentialStatus status = 1;

  // updated_at is when the status was last updated
  google.protobuf.Timestamp updated_at = 2 [
    (gogoproto.stdtime) = true,
    (gogoproto.nullable) = false,
    (amino.dont_omitempty) = true
  ];

  // revocation_reason explains why credential was revoked/suspended
  string revocation_reason = 3;
}
```

### VerifiableCredential

```sh
ignite s type VerifiableCredential Id Context Type Issuer IssuedAt CredentialSubject ValidFrom ValidUntil CredentialStatus Proof CredentialType Holder Metadata RefreshService --module iam
```

Update types to match W3C Verifiable Credential specification

```proto
syntax = "proto3";
package acmain.iam.v1;

import "acmain/iam/v1/credential_proof.proto";
import "acmain/iam/v1/credential_status_info.proto";
import "acmain/iam/v1/credential_subject.proto";
import "acmain/iam/v1/enums.proto";
import "amino/amino.proto";
import "gogoproto/gogo.proto";
import "google/protobuf/timestamp.proto";

option go_package = "acmain/x/iam/types";

// VerifiableCredential represents a W3C Verifiable Credential
message VerifiableCredential {
  option (gogoproto.equal) = true;
  option (amino.name) = "acmain/x/iam/VerifiableCredential";

  // id is the unique identifier for this credential
  string id = 1;

  // context is the JSON-LD context
  repeated string context = 2;

  // type contains credential types (includes "VerifiableCredential")
  repeated string type = 3;

  // issuer is the address/DID that issued the credential
  string issuer = 4;

  // issued_at is the block timestamp of issuance
  google.protobuf.Timestamp issued_at = 5 [
    (gogoproto.nullable) = false,
    (gogoproto.stdtime) = true,
    (amino.dont_omitempty) = true
  ];

  // credential_subject contains the subject and claims
  CredentialSubject credential_subject = 6 [
    (gogoproto.nullable) = false,
    (amino.dont_omitempty) = true
  ];

  // valid_from is the earliest validity time
  google.protobuf.Timestamp valid_from = 7 [
    (gogoproto.nullable) = false,
    (gogoproto.stdtime) = true,
    (amino.dont_omitempty) = true
  ];

  // valid_until is the expiration time
  google.protobuf.Timestamp valid_until = 8 [
    (gogoproto.nullable) = false,
    (gogoproto.stdtime) = true,
    (amino.dont_omitempty) = true
  ];

  // credential_status tracks revocation/suspension
  CredentialStatusInfo credential_status = 9 [
    (gogoproto.nullable) = false,
    (amino.dont_omitempty) = true
  ];

  // proof contains the cryptographic proof
  CredentialProof proof = 10 [
    (gogoproto.nullable) = false,
    (amino.dont_omitempty) = true
  ];

  // credential_type is the semantic credential type
  CredentialType credential_type = 11;

  // holder is the DID of the entity holding the credential
  string holder = 12;

  // metadata contains issuer-specific attributes
  map<string, string> metadata = 13;

  // refresh_service is the credential renewal endpoint
  string refresh_service = 14;
}
```

### DeviceKey

```sh
ignite s type DeviceKey DeviceId PublicKey KeyType Owner DeviceType Location RegisteredAt LastRotationAt RevokedAt Metadata Active --module iam
```

Update types for IoT device key management

```proto
syntax = "proto3";
package acmain.iam.v1;

import "acmain/iam/v1/enums.proto";
import "amino/amino.proto";
import "gogoproto/gogo.proto";
import "google/protobuf/timestamp.proto";

option go_package = "acmain/x/iam/types";

// DeviceKey represents an IoT device key for access control
message DeviceKey {
  option (gogoproto.equal) = true;
  option (amino.name) = "acmain/x/iam/DeviceKey";

  // device_id is the unique device identifier
  string device_id = 1;

  // public_key is the device's public key bytes
  bytes public_key = 2;

  // key_type specifies the cryptographic algorithm
  KeyType key_type = 3;

  // owner is the Cosmos address owning the device
  string owner = 4;

  // device_type categorizes the device (smart_lock, sensor, witness_node)
  string device_type = 5;

  // location is the physical location of the device
  string location = 6;

  // registered_at is the block timestamp of registration
  google.protobuf.Timestamp registered_at = 7 [
    (gogoproto.nullable) = false,
    (gogoproto.stdtime) = true,
    (amino.dont_omitempty) = true
  ];

  // last_rotation_at is the last key rotation timestamp
  google.protobuf.Timestamp last_rotation_at = 8 [(gogoproto.stdtime) = true];

  // revoked_at is the revocation timestamp
  google.protobuf.Timestamp revoked_at = 9 [(gogoproto.stdtime) = true];

  // metadata contains device-specific attributes
  map<string, string> metadata = 10;

  // active indicates if the device key is active
  bool active = 11;
}
```

### Transactions

The Identity module provides comprehensive transaction messages for managing DIDs, credentials, and device keys.

#### DID Management

```sh
# Register a new DID
ignite s message RegisterDID Controller DID DIDMethod PublicKey KeyType ServiceEndpoints AlsoKnownAs Metadata --module iam --response DIDDocument

# Update DID document
ignite s message UpdateDIDDocument Controller DID ServiceEndpoints AlsoKnownAs Metadata --module iam --response DIDDocument

# Deactivate DID
ignite s message DeactivateDID Controller DID --module iam

# Add public key to DID
ignite s message AddPublicKey Controller DID KeyId PublicKey KeyType Purpose --module iam --response PublicKeyInfo

# Revoke public key from DID
ignite s message RevokePublicKey Controller DID KeyId --module iam
```

#### Credential Management

```sh
# Issue a new verifiable credential
ignite s message IssueCredential Issuer Subject CredentialType Claims ValidFrom ValidUntil Metadata RefreshService --module iam --response CredentialId:string,VerifiableCredential

# Revoke a credential
ignite s message RevokeCredential Issuer CredentialId RevocationReason --module iam

# Suspend a credential
ignite s message SuspendCredential Issuer CredentialId SuspensionReason --module iam

# Resume a suspended credential
ignite s message ResumeCredential Issuer CredentialId --module iam
```

#### Device Key Management

```sh
# Register a device key
ignite s message RegisterDeviceKey Owner DeviceId PublicKey KeyType DeviceType Location Metadata --module iam --response DeviceKey

# Revoke a device key
ignite s message RevokeDeviceKey Owner DeviceId RevocationReason --module iam

# Rotate a device key
ignite s message RotateDeviceKey Owner DeviceId NewPublicKey KeyType --module iam --response DeviceKey
```

### Events

The Identity module emits events for all state-changing operations. These are automatically generated proto files.

#### DID Events

- `EventDIDRegistered`: Emitted when a new DID is registered
  - `did` (string): The registered DID
  - `controller` (string): Controller address

- `EventDIDUpdated`: Emitted when a DID document is updated
  - `did` (string): The updated DID

- `EventPublicKeyRevoked`: Emitted when a public key is revoked
  - `did` (string): DID whose key was revoked
  - `key_id` (string): Revoked key identifier

#### Credential Events

- `EventCredentialRevoked`: Emitted when a credential is revoked
  - `credential_id` (string): Revoked credential ID
  - `issuer` (string): Issuer address
  - `reason` (string): Revocation reason

- `EventCredentialSuspended`: Emitted when a credential is suspended
  - `credential_id` (string): Suspended credential ID
  - `issuer` (string): Issuer address
  - `reason` (string): Suspension reason

- `EventCredentialResumed`: Emitted when a credential is resumed
  - `credential_id` (string): Resumed credential ID
  - `issuer` (string): Issuer address

#### Device Key Events

- `EventDeviceKeyRegistered`: Emitted when a device key is registered
  - `device_id` (string): Device identifier
  - `owner` (string): Owner address
  - `location` (string): Physical location

- `EventDeviceKeyRevoked`: Emitted when a device key is revoked
  - `device_id` (string): Device identifier
  - `owner` (string): Owner address
  - `reason` (string): Revocation reason

- `EventDeviceKeyRotated`: Emitted when a device key is rotated
  - `device_id` (string): Device identifier
  - `owner` (string): Owner address
