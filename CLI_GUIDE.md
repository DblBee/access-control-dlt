# Access Control DLT CLI Guide

## Overview

`acmaind` is the command-line interface for the Access Control Distributed Ledger Technology (DLT) node. This CLI is built using the Cosmos SDK and provides comprehensive commands for managing nodes, keys, transactions, queries, and the blockchain network.

## Table of Contents

1. [Installation](#installation)
2. [Global Flags](#global-flags)
3. [Node Management](#node-management)
4. [Key Management](#key-management)
5. [Transaction Commands](#transaction-commands)
6. [Query Commands](#query-commands)
7. [Genesis Management](#genesis-management)
8. [Custom Modules](#custom-modules)
9. [Testing & Development](#testing--development)
10. [Advanced Commands](#advanced-commands)

---

## Installation

Build the binary from source:

```bash
make install
```

Or run directly:

```bash
go run ./cmd/acmaind [command]
```

---

## Global Flags

These flags are available for all commands:

| Flag | Description | Default |
|------|-------------|---------|
| `--home` | Directory for config and data | `~/.acmain` |
| `--log_format` | Logging format (json\|plain) | `plain` |
| `--log_level` | Logging level (trace\|debug\|info\|warn\|error\|fatal\|panic\|disabled) | `info` |
| `--log_no_color` | Disable colored logs | `false` |
| `--trace` | Print full stack trace on errors | `false` |

**Example:**
```bash
acmaind status --log_level debug --home ./custom-home
```

---

## Node Management

### Initialize a Node

Initialize a new node with configuration files.

```bash
acmaind init [moniker] [flags]
```

**Flags:**
- `--chain-id` - Chain ID for the genesis file
- `--consensus-key-algo` - Algorithm for consensus key (default: `ed25519`)
- `--default-denom` - Default denomination in genesis (default: `stake`)
- `--home` - Node's home directory
- `--initial-height` - Initial block height (default: `1`)
- `-o, --overwrite` - Overwrite existing genesis.json
- `--recover` - Recover existing key from seed phrase

**Example:**
```bash
acmaind init mynode --chain-id acmain-1 --default-denom token
```

### Start the Node

Run the full node with CometBFT.

```bash
acmaind start [flags]
```

**Key Flags:**
- `--api.enable` - Enable API server
- `--api.address` - API server address (default: `tcp://localhost:1317`)
- `--grpc.enable` - Enable gRPC server (default: `true`)
- `--grpc.address` - gRPC server address (default: `localhost:9090`)
- `--rpc.laddr` - RPC listen address (default: `tcp://127.0.0.1:26657`)
- `--p2p.laddr` - P2P listen address (default: `tcp://0.0.0.0:26656`)
- `--p2p.seeds` - Comma-delimited seed nodes (ID@host:port)
- `--p2p.persistent_peers` - Comma-delimited persistent peers
- `--minimum-gas-prices` - Minimum gas prices (e.g., `0.01token`)
- `--pruning` - Pruning strategy (default|nothing|everything|custom)
- `--halt-height` - Block height to halt the chain
- `--grpc-only` - Start in gRPC query-only mode

**Example:**
```bash
acmaind start --api.enable --minimum-gas-prices 0.001token --pruning custom --pruning-keep-recent 100000
```

### Check Node Status

Query the remote node for status.

```bash
acmaind status
```

**Example Output:**
```json
{
  "NodeInfo": {
    "protocol_version": {...},
    "id": "...",
    "network": "acmain-1"
  },
  "SyncInfo": {
    "latest_block_hash": "...",
    "latest_block_height": "12345"
  }
}
```

### Export State

Export the application state to JSON.

```bash
acmaind export [flags]
```

**Flags:**
- `--for-zero-height` - Export for a zero-height genesis
- `--height` - Export state at specific height (-1 for latest)
- `--jail-allowed-addrs` - Comma-separated list of addresses to unjail

**Example:**
```bash
acmaind export --height 100000 > state_export.json
```

---

## Key Management

Manage cryptographic keys using the keyring.

### Add a New Key

Create or recover a key.

```bash
acmaind keys add [name] [flags]
```

**Flags:**
- `--recover` - Recover key from mnemonic
- `--keyring-backend` - Keyring backend (os|file|test|memory)
- `--algo` - Key algorithm (secp256k1|ed25519|sr25519)
- `--account` - Account number for HD derivation
- `--index` - Address index for HD derivation

**Example:**
```bash
# Create new key
acmaind keys add alice

# Recover from mnemonic
acmaind keys add bob --recover

# Use test keyring
acmaind keys add charlie --keyring-backend test
```

### List Keys

Display all keys in the keyring.

```bash
acmaind keys list [flags]
```

**Example:**
```bash
acmaind keys list --keyring-backend test --output json
```

### Show Key Information

Display details for a specific key.

```bash
acmaind keys show [name] [flags]
```

**Flags:**
- `-a, --address` - Output address only
- `-p, --pubkey` - Output public key only
- `--bech` - Bech32 prefix (acc|val|cons)

**Example:**
```bash
# Show full key info
acmaind keys show alice

# Show only address
acmaind keys show alice --address

# Show validator operator address
acmaind keys show alice --bech val
```

### Delete a Key

Remove a key from the keyring.

```bash
acmaind keys delete [name] [flags]
```

**Example:**
```bash
acmaind keys delete alice -y
```

### Export Private Key

Export a private key for backup.

```bash
acmaind keys export [name] [flags]
```

**Example:**
```bash
acmaind keys export alice > alice_key.txt
```

### Import Private Key

Import a previously exported key.

```bash
acmaind keys import [name] [keyfile] [flags]
```

**Example:**
```bash
acmaind keys import alice alice_key.txt
```

---

## Transaction Commands

### Bank Module

Send tokens between accounts.

```bash
acmaind tx bank send [from] [to] [amount] [flags]
```

**Example:**
```bash
acmaind tx bank send alice acmain1xyz... 1000token \
  --chain-id acmain-1 \
  --gas auto \
  --gas-adjustment 1.3 \
  --fees 100token
```

### Sign a Transaction

Sign a transaction generated offline.

```bash
acmaind tx sign [file] [flags]
```

**Flags:**
- `--from` - Key name to sign with
- `--offline` - Sign in offline mode
- `--signature-only` - Print only signature

**Example:**
```bash
acmaind tx sign unsigned.json --from alice > signed.json
```

### Broadcast a Transaction

Broadcast a signed transaction.

```bash
acmaind tx broadcast [file] [flags]
```

**Flags:**
- `--broadcast-mode` - Transaction broadcasting mode (sync|async|block)

**Example:**
```bash
acmaind tx broadcast signed.json --broadcast-mode block
```

### Multi-Signature Transactions

Create and sign multisig transactions.

```bash
# Generate multisig transaction
acmaind tx multi-sign [file] [multisig-name] [signature]... [flags]

# Sign by each party
acmaind tx sign unsigned.json --from alice --multisig multisig_addr > alice_sig.json
acmaind tx sign unsigned.json --from bob --multisig multisig_addr > bob_sig.json

# Combine signatures
acmaind tx multi-sign unsigned.json multisig alice_sig.json bob_sig.json > signed_multisig.json

# Broadcast
acmaind tx broadcast signed_multisig.json
```

### Encode/Decode Transactions

```bash
# Encode transaction to binary
acmaind tx encode [file]

# Decode binary transaction
acmaind tx decode [amino-byte-string]
```

**Example:**
```bash
acmaind tx encode tx.json > tx.bin
acmaind tx decode $(cat tx.bin)
```

### Simulate Transaction

Estimate gas for a transaction.

```bash
acmaind tx simulate [file]
```

**Example:**
```bash
acmaind tx simulate unsigned.json
```

---

## Query Commands

### Block Queries

Query blocks by height, hash, or events.

```bash
# Query block by height
acmaind query block [height]

# Query block results
acmaind query block-results [height]

# Query blocks by events
acmaind query blocks --query "tx.height>100 AND tx.height<200"
```

**Example:**
```bash
acmaind query block 12345
acmaind query block-results 12345
```

### Transaction Queries

Query transactions by hash or events.

```bash
# Query by hash
acmaind query tx [hash]

# Query by events
acmaind query txs --query "message.sender='acmain1xyz...'"

# Wait for transaction
acmaind query wait-tx [hash]
```

**Example:**
```bash
acmaind query tx 5B3C0F4A2E8D9B1C4A6F7E8D9C0B1A2F3E4D5C6B7A8D9E0F1C2B3A4D5E6F7A8B
acmaind query txs --query "message.action='/cosmos.bank.v1beta1.MsgSend'" --limit 10
```

### Account Queries

Query account information.

```bash
acmaind query auth account [address]
```

**Example:**
```bash
acmaind query auth account acmain1xyz...
```

### Bank Balances

Query account balances.

```bash
# Query all balances
acmaind query bank balances [address]

# Query specific denomination
acmaind query bank balance [address] [denom]

# Query total supply
acmaind query bank total

# Query supply of specific denom
acmaind query bank total [denom]
```

**Example:**
```bash
acmaind query bank balances acmain1xyz...
acmaind query bank balance acmain1xyz... token
```

### Staking Queries

Query staking information.

```bash
# List all validators
acmaind query staking validators

# Query specific validator
acmaind query staking validator [validator-addr]

# Query delegations
acmaind query staking delegations [delegator-addr]

# Query delegation to specific validator
acmaind query staking delegation [delegator-addr] [validator-addr]

# Query unbonding delegations
acmaind query staking unbonding-delegations [delegator-addr]
```

**Example:**
```bash
acmaind query staking validators --output json
acmaind query staking validator acmainvaloper1xyz...
```

### Distribution Queries

Query distribution/rewards information.

```bash
# Query rewards
acmaind query distribution rewards [delegator-addr]

# Query commission
acmaind query distribution commission [validator-addr]

# Query community pool
acmaind query distribution community-pool
```

**Example:**
```bash
acmaind query distribution rewards acmain1xyz...
```

### Governance Queries

Query governance proposals and votes.

```bash
# List proposals
acmaind query gov proposals

# Query specific proposal
acmaind query gov proposal [proposal-id]

# Query votes for proposal
acmaind query gov votes [proposal-id]

# Query specific vote
acmaind query gov vote [proposal-id] [voter-addr]
```

**Example:**
```bash
acmaind query gov proposals --status voting_period
acmaind query gov proposal 1
```

---

## Genesis Management

Manage genesis file and genesis transactions.

### Add Genesis Account

Add an account to the genesis file.

```bash
acmaind genesis add-genesis-account [address] [coins] [flags]
```

**Example:**
```bash
acmaind genesis add-genesis-account acmain1xyz... 1000000token
```

### Bulk Add Genesis Accounts

Add multiple accounts from a JSON file.

```bash
acmaind genesis bulk-add-genesis-account [accounts-file]
```

**Example accounts.json:**
```json
[
  {"address": "acmain1...", "coins": ["1000000token"]},
  {"address": "acmain2...", "coins": ["2000000token"]}
]
```

```bash
acmaind genesis bulk-add-genesis-account accounts.json
```

### Generate Genesis Transaction

Create a genesis transaction for a validator.

```bash
acmaind genesis gentx [key-name] [amount] [flags]
```

**Flags:**
- `--commission-rate` - Validator commission rate
- `--commission-max-rate` - Max commission rate
- `--commission-max-change-rate` - Max commission change rate
- `--min-self-delegation` - Minimum self delegation

**Example:**
```bash
acmaind genesis gentx alice 1000000token \
  --chain-id acmain-1 \
  --commission-rate 0.1 \
  --commission-max-rate 0.2 \
  --commission-max-change-rate 0.01 \
  --min-self-delegation 1
```

### Collect Genesis Transactions

Collect genesis transactions and create final genesis.json.

```bash
acmaind genesis collect-gentxs
```

**Example:**
```bash
acmaind genesis collect-gentxs --home ./node1
```

### Validate Genesis

Verify the genesis file is valid.

```bash
acmaind genesis validate [genesis-file]
```

**Example:**
```bash
acmaind genesis validate ~/.acmain/config/genesis.json
```

---

## Custom Modules

### Identity Module

Manage decentralized identifiers (DIDs), device keys, and verifiable credentials.

#### Query Commands

```bash
# Query DID
acmaind query identity did [did-id]

# Query all DIDs
acmaind query identity di-ds

# Query DIDs by controller
acmaind query identity di-ds-by-controller [controller-address]

# Query device key
acmaind query identity device-key [key-id]

# Query device keys by owner
acmaind query identity device-keys-by-owner [owner-address]

# Query device keys by location
acmaind query identity device-keys-by-location [location]

# Query credential
acmaind query identity credential [credential-id]

# Query credentials by issuer
acmaind query identity credentials-by-issuer [issuer-did]

# Query credentials by subject
acmaind query identity credentials-by-subject [subject-did]

# Validate credential
acmaind query identity is-credential-valid [credential-id]

# Query public key
acmaind query identity public-key [key-id]
```

**Examples:**
```bash
acmaind query identity did did:acmain:abc123
acmaind query identity device-keys-by-owner acmain1xyz...
acmaind query identity credential cred_12345
acmaind query identity is-credential-valid cred_12345
```

#### Transaction Commands

```bash
# Create DID
acmaind tx identity create-did [flags]

# Update DID
acmaind tx identity update-did [did-id] [flags]

# Deactivate DID
acmaind tx identity deactivate-did [did-id]

# Register device key
acmaind tx identity register-device-key [flags]

# Revoke device key
acmaind tx identity revoke-device-key [key-id]

# Issue credential
acmaind tx identity issue-credential [flags]

# Revoke credential
acmaind tx identity revoke-credential [credential-id]
```

**Examples:**
```bash
acmaind tx identity create-did --from alice --chain-id acmain-1
acmaind tx identity register-device-key --owner acmain1xyz... --location "Building A" --from alice
acmaind tx identity issue-credential --subject did:acmain:123 --type "AccessCredential" --from issuer
```

### Asset Management Module

Manage digital assets with states, types, and controllers.

#### Query Commands

```bash
# Query asset
acmaind query assetmgmt asset [asset-id]

# Query assets by controller
acmaind query assetmgmt assets-by-controller [controller-address]

# Query assets by location
acmaind query assetmgmt assets-by-location [location]

# Query assets by state
acmaind query assetmgmt assets-by-state [state]

# Query assets by type
acmaind query assetmgmt assets-by-type [type]
```

**Examples:**
```bash
acmaind query assetmgmt asset asset_001
acmaind query assetmgmt assets-by-controller acmain1xyz...
acmaind query assetmgmt assets-by-location "Warehouse 1"
acmaind query assetmgmt assets-by-state active
acmaind query assetmgmt assets-by-type "IoT Device"
```

#### Transaction Commands

```bash
# Create asset
acmaind tx assetmgmt create-asset [flags]

# Update asset
acmaind tx assetmgmt update-asset [asset-id] [flags]

# Transfer asset
acmaind tx assetmgmt transfer-asset [asset-id] [new-controller]

# Change asset state
acmaind tx assetmgmt change-asset-state [asset-id] [new-state]

# Delete asset
acmaind tx assetmgmt delete-asset [asset-id]
```

**Examples:**
```bash
acmaind tx assetmgmt create-asset --type "Sensor" --location "Room 101" --from alice
acmaind tx assetmgmt transfer-asset asset_001 acmain1newowner... --from alice
acmaind tx assetmgmt change-asset-state asset_001 inactive --from alice
```

### Permission Module

Manage access control and permissions.

#### Query Commands

```bash
# Query module parameters
acmaind query permission params
```

#### Transaction Commands

```bash
# Grant permission
acmaind tx permission grant-permission [flags]

# Revoke permission
acmaind tx permission revoke-permission [flags]

# Update permission
acmaind tx permission update-permission [flags]
```

**Examples:**
```bash
acmaind tx permission grant-permission --grantee acmain1xyz... --resource asset_001 --action read --from admin
acmaind tx permission revoke-permission --grantee acmain1xyz... --resource asset_001 --from admin
```

---

## Testing & Development

### In-Place Testnet

Create a local testnet from mainnet state.

```bash
acmaind in-place-testnet [chain-id] [validator-operator-addr] [flags]
```

**Flags:**
- `--home` - Node's home directory
- `--validator-privkey` - Validator private key
- `--accounts-to-fund` - Comma-separated accounts to fund

**Example:**
```bash
acmaind in-place-testnet testing-1 acmainvaloper1w7f... \
  --home ~/.acmain/validator1 \
  --validator-privkey="6dq+/KHNvyiw2..." \
  --accounts-to-fund="acmain1f7t...,acmain1qvu..."
```

### Multi-Node Testnet

Initialize a multi-validator testnet configuration.

```bash
acmaind multi-node [flags]
```

**Flags:**
- `--v` - Number of validators
- `--output-dir` - Directory for config files
- `--starting-ip-address` - Starting IP address
- `--key-type` - Key algorithm

**Example:**
```bash
acmaind multi-node --v 4 --output-dir ./testnet --starting-ip-address 192.168.1.2
```

### Debug Commands

Tools for debugging the application.

```bash
# Print address from public key
acmaind debug addr [address]

# Print public key from hex/bech32
acmaind debug pubkey [pubkey]

# Print raw bytes
acmaind debug raw-bytes [hex-string]
```

**Example:**
```bash
acmaind debug addr acmain1xyz...
acmaind debug pubkey acmainpub1...
```

---

## Advanced Commands

### Snapshots

Manage local state snapshots.

```bash
# List snapshots
acmaind snapshots list

# Restore from snapshot
acmaind snapshots restore [height] [format]

# Export snapshot
acmaind snapshots export

# Delete snapshot
acmaind snapshots delete [height] [format]
```

**Example:**
```bash
acmaind snapshots list
acmaind snapshots restore 100000 1
```

### Pruning

Prune historical state data.

```bash
acmaind prune [flags]
```

**Flags:**
- `--pruning` - Pruning strategy
- `--pruning-keep-recent` - Number of recent heights to keep
- `--pruning-interval` - Pruning interval

**Example:**
```bash
acmaind prune --pruning custom --pruning-keep-recent 100000 --pruning-interval 10
```

### Rollback

Rollback state by one height.

```bash
acmaind rollback [flags]
```

**Example:**
```bash
acmaind rollback --home ~/.acmain
```

### Configuration

Manage application configuration.

```bash
# Show configuration
acmaind config

# Set configuration value
acmaind config [key] [value]

# Initialize client config
acmaind config init
```

**Example:**
```bash
acmaind config chain-id acmain-1
acmaind config keyring-backend test
acmaind config node tcp://localhost:26657
```

### CometBFT Commands

Interact with CometBFT (Tendermint).

```bash
# Show CometBFT version
acmaind comet version

# Show node ID
acmaind comet show-node-id

# Show validator
acmaind comet show-validator

# Show address
acmaind comet show-address

# Reset data
acmaind comet unsafe-reset-all
```

**Example:**
```bash
acmaind comet show-node-id
acmaind comet show-validator
```

### Version

Display version information.

```bash
acmaind version [flags]
```

**Flags:**
- `--long` - Print long version information

**Example:**
```bash
acmaind version
acmaind version --long
```

---

## Common Workflows

### Setting Up a Validator Node

```bash
# 1. Initialize node
acmaind init myvalidator --chain-id acmain-1

# 2. Add genesis account
acmaind genesis add-genesis-account $(acmaind keys show validator -a) 1000000token

# 3. Create genesis transaction
acmaind genesis gentx validator 500000token --chain-id acmain-1

# 4. Collect genesis transactions
acmaind genesis collect-gentxs

# 5. Validate genesis
acmaind genesis validate

# 6. Start node
acmaind start
```

### Joining an Existing Network

```bash
# 1. Initialize node
acmaind init mynode --chain-id acmain-1

# 2. Download genesis file
wget https://example.com/genesis.json -O ~/.acmain/config/genesis.json

# 3. Configure seeds/peers
acmaind config p2p.seeds "node1@ip1:26656,node2@ip2:26656"

# 4. Start node
acmaind start
```

### Creating and Broadcasting a Transaction

```bash
# 1. Create transaction
acmaind tx bank send alice acmain1xyz... 1000token \
  --chain-id acmain-1 \
  --generate-only > unsigned.json

# 2. Sign transaction
acmaind tx sign unsigned.json --from alice > signed.json

# 3. Broadcast transaction
acmaind tx broadcast signed.json --broadcast-mode block

# 4. Query transaction
acmaind query tx <tx-hash>
```

---

## Environment Variables

- `ACMAIN_HOME` - Override default home directory
- `ACMAIN_KEYRING_BACKEND` - Default keyring backend
- `ACMAIN_CHAIN_ID` - Default chain ID
- `ACMAIN_NODE` - Default node RPC address

**Example:**
```bash
export ACMAIN_HOME=./custom-home
export ACMAIN_KEYRING_BACKEND=test
export ACMAIN_CHAIN_ID=acmain-1
export ACMAIN_NODE=tcp://localhost:26657
```

---

## Tips and Best Practices

1. **Use Test Keyring for Development**: `--keyring-backend test` avoids password prompts
2. **Estimate Gas First**: Use `--gas auto --gas-adjustment 1.3` for transactions
3. **Save Transaction Outputs**: Use `--output json` and pipe to files for processing
4. **Monitor Logs**: Use `--log_level debug` when troubleshooting
5. **Backup Keys**: Always export and securely store private keys
6. **Use Aliases**: Create shell aliases for common commands
7. **Check Chain State**: Use `acmaind status` before broadcasting transactions
8. **Validate Before Broadcasting**: Use `--generate-only` and review transactions

---

## Troubleshooting

### Common Issues

**Connection Refused:**
```bash
# Check if node is running
acmaind status

# Verify RPC address
acmaind config node tcp://localhost:26657
```

**Account Sequence Mismatch:**
```bash
# Query account to get current sequence
acmaind query auth account <address>

# Use correct sequence in transaction
acmaind tx bank send ... --sequence <correct-sequence>
```

**Insufficient Fees:**
```bash
# Increase fees or gas
acmaind tx bank send ... --fees 200token --gas 200000
```

**Key Not Found:**
```bash
# Check keyring backend
acmaind keys list --keyring-backend <os|file|test>
```

---

## Additional Resources

- **Cosmos SDK Documentation**: https://docs.cosmos.network
- **CometBFT Documentation**: https://docs.cometbft.com
- **Project Repository**: https://github.com/your-org/access-control-dlt
- **Chain Explorer**: https://explorer.acmain.network

---

## Command Quick Reference

| Category | Command | Purpose |
|----------|---------|---------|
| Node | `acmaind init` | Initialize node |
| Node | `acmaind start` | Start node |
| Node | `acmaind status` | Check node status |
| Keys | `acmaind keys add` | Create key |
| Keys | `acmaind keys list` | List keys |
| Keys | `acmaind keys show` | Show key info |
| TX | `acmaind tx bank send` | Send tokens |
| TX | `acmaind tx sign` | Sign transaction |
| TX | `acmaind tx broadcast` | Broadcast transaction |
| Query | `acmaind query block` | Query block |
| Query | `acmaind query tx` | Query transaction |
| Query | `acmaind query bank balances` | Query balances |
| Genesis | `acmaind genesis gentx` | Generate genesis TX |
| Genesis | `acmaind genesis collect-gentxs` | Collect genesis TXs |
| Identity | `acmaind query identity did` | Query DID |
| Identity | `acmaind tx identity create-did` | Create DID |
| Asset | `acmaind query assetmgmt asset` | Query asset |
| Asset | `acmaind tx assetmgmt create-asset` | Create asset |

---

*Last Updated: November 2024*
*CLI Version: Compatible with Cosmos SDK v0.50.x*
