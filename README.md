# Marriage Registry

An on-chain marriage registration program deployed on Solana mainnet. It provides a permissionless, tamper-proof mechanism for recording and verifying marriage records, anchored to the immutability of the Solana blockchain.

## Deployment

| Network | Program ID |
|---------|-----------|
| Mainnet | `CmkicBWwA7dVBKPXbZ5AGHXQGGqNhyS7rY8skEv6NxMy` |

View on Solana Explorer: [https://explorer.solana.com/address/CmkicBWwA7dVBKPXbZ5AGHXQGGqNhyS7rY8skEv6NxMy](https://explorer.solana.com/address/CmkicBWwA7dVBKPXbZ5AGHXQGGqNhyS7rY8skEv6NxMy)

## Overview

Marriage Registry is an Anchor-based Solana program that enables the creation and querying of on-chain marriage records. Each record is stored as a Program Derived Address (PDA), making every registration uniquely addressable, publicly verifiable, and permanently stored without reliance on any centralized authority.

## Tech Stack

- **Runtime:** Solana
- **Framework:** Anchor
- **Language:** Rust (program), TypeScript (tests and client)
- **Test Runner:** ts-mocha
- **Package Manager:** Yarn

## Repository Structure

```
marriage_registry/
├── programs/
│   └── marriage_registry/
│       └── src/
│           └── lib.rs          # Program entry point and instruction handlers
├── migrations/                 # Anchor deployment migrations
├── tests/                      # TypeScript integration tests
├── Anchor.toml                 # Anchor workspace configuration
├── Cargo.toml                  # Rust workspace manifest
└── tsconfig.json               # TypeScript configuration
```

## Getting Started

Clone the repository and install dependencies:

```bash
git clone https://github.com/Shradhesh71/marriage_registry.git
cd marriage_registry
yarn install
```

Build the program:

```bash
anchor build
```

Run the test suite against a local validator:

```bash
anchor test
```
## License

MIT