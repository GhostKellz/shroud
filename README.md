# 🕸️ Shroud

> A high-performance, zero-trust cryptographic and network framework for Ghostchain and the Web5 ecosystem.

---

## 🔥 What is Shroud?

**Shroud** is a modular framework for secure, verifiable, high-speed communication over modern internet infrastructure. It bridges **Web2 protocols (DNS, HTTP3, QUIC)** with **Web3 primitives (DIDs, ZNS, QID, cryptographic identity)**.

It powers key components of the **Ghostchain** protocol stack, and enables zero-trust service layers for the decentralized internet.

---

## 🧹 Core Modules

| Module        | Purpose                                                                  |
| ------------- | ------------------------------------------------------------------------ |
| `ghostwire`   | High-speed networking: QUIC, HTTP/3, DNS, secure tunnels                 |
| `ghostcipher` | Cryptographic primitives: zcrypto, zsig, post-quantum readiness          |
| `keystone`    | Transaction ledger and state layer: records, tokens, chain state         |
| `sigil`       | Identity resolution: Ghostchain ID (GID), DIDs, QIDs, decentralized auth |
| `zns`         | Domain name system: ZNS, .ghost/.bc/.gcc/.sig resolution                 |
| `shadowcraft` | Identity enforcement and zero-trust logic engine (AuthContext, policies) |
| `guardian`    | Multi-sig, watchdog enforcement, identity-level access control           |
| `covenant`    | Smart contract policy ruleset engine for conditional validation          |
| `gwallet`     | GhostWallet: Secure programmable wallet with Sigil identity integration |

---

## 💡 Modules Overview

* **`ghostwire`** – Networking core
* **`ghostcipher`** – Cryptography + signing
* **`keystone`** – Ledger and state
* **`sigil`** – Identity stack for Ghostchain ID (GID)
* **`zns`** – Name system (like ENS)
* **`shadowcraft`** – Runtime identity enforcement (AuthContext)
* **`guardian`** – Access and signature enforcement
* **`covenant`** – Contract rules, validation logic
* **`gwallet`** – GhostWallet CLI and library for secure wallet operations

---

## 🚀 Quick Start

### GhostWallet (gwallet)
```bash
# Build and run GhostWallet
zig build gwallet

# Create a new wallet
./zig-out/bin/gwallet generate --type ed25519 --name myname

# Import existing wallet
./zig-out/bin/gwallet import --mnemonic "word1 word2 ..."

# Check balance
./zig-out/bin/gwallet balance --token gcc

# Send tokens
./zig-out/bin/gwallet send --to recipient.ghost --amount 420 --token gcc

# Start Web3 bridge for dApp integration
./zig-out/bin/gwallet --bridge --port 8080
```

### Library Usage
```zig
const shroud = @import("shroud");

// Access GhostWallet functionality
const wallet = try shroud.gwallet.createWallet(allocator, "passphrase", .hybrid);
defer wallet.deinit();

// Use other Shroud modules
const identity = try shroud.sigil.createIdentity(allocator);
const domain_result = try shroud.zns.resolve("example.ghost");
```

---

> The Shroud framework is the foundation of Ghostchain's gateway to Web5 — where traditional protocols meet decentralized trust.

