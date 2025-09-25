<p align="center">
  <img src="assets/icons/shroud.png" alt="Shroud Logo" width="200"/>
</p>

# 🕶️ Shroud

> Identity & Privacy Layer for Zero-Trust Systems

**Shroud** is a modular identity and privacy framework designed for secure access control, anonymous delegation, and policy enforcement in decentralized environments.

## DISCLAIMER

⚠️ **EXPERIMENTAL LIBRARY - FOR LAB/PERSONAL USE** ⚠️

This is an experimental library under active development. It is
intended for research, learning, and personal projects. The API is subject
to change!

---

## ✨ Features

* 🔐 **Decentralized Identity (DID)** abstraction
* 🧠 **Guardian Policy Engine**

  * Role-based and permission-based access
  * Hierarchical trust delegation
* 🕵️ **Privacy Enforcement**

  * Ephemeral identities & tokenization
  * Non-linkable session tokens
* 📜 **Access Contracts**

  * Signed, verifiable access grants
  * Policy-bound delegation tokens
* ⚖️ **Composable with Keystone**

  * Plug into any ledger or app layer
  * Use with Keystone, Ghostchain, or standalone

---

## 🧩 Modules

### `guardian.zig`

Policy enforcement engine. Defines:

* `Permission`
* `Role`
* `GuardianError`

### `identity.zig`

Identity model & delegation logic:

* Ephemeral identity signing
* DID generation & verification

### `access_token.zig`

Access token generation and validation:

* Signature-bound permissions
* Expiration & time windows

---

## 🔗 Integrations

* ✅ Keystone (consensus layer)
* ✅ Ghostchain (zk-powered L2)
* ✅ ZNS (identity binding)
* ✅ ZVM (smart identity-aware execution)

---

## 🚧 Roadmap

* [x] Guardian permission framework
* [x] Identity + token delegation
* [ ] zkProof-based identity attestations
* [ ] WASM-compatible policy validation
* [ ] Integration with ZNS + walletd

---

## 📂 Repo Structure

```
shroud/
├── src/
│   ├── guardian.zig
│   ├── identity.zig
│   ├── access_token.zig
├── tests/
│   ├── guardian_test.zig
│   └── identity_test.zig
├── README.md
└── build.zig
```

---

## 🛠️ Build

```bash
zig build
zig build test
```

---

## 🧠 Philosophy

Shroud is designed to be:

* 🔌 **Composable** — drop into any stack
* 🕳️ **Opaque by default** — zero-knowledge friendly
* 💡 **Minimalist** — core logic only, no runtime bloat

> Shroud doesn’t store state. It validates intent.

---

## 📜 License

MIT

---

## 👤 Author

**GhostKellz**  |  [https://ghostkellz.sh](https://ghostkellz.sh)

