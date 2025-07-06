# 🧱 Shroud Integration TODO

> Migrate and integrate archived Ghostchain projects into the new `shroud` modular framework.  
Legacy crates are preserved in `/archived` for reference, source reuse, and documentation.

---

## 📦 Migration Overview

| Legacy Project | New Module         | Notes |
|----------------|--------------------|-------|
| `zcrypto`      | `ghostcipher`      | Migrate cryptographic primitives, keygen, hashing |
| `zsig`         | `ghostcipher`      | Signing/verification will become a submodule |
| `realid`       | `sigil`            | Migrate identity resolution, DID parsing, QID auth |
| `zns`          | `zns`              | Reuse ZNS logic: supports `.ghost`, `.bc`, `.gcc`, `.gman`, etc |
| `zquic`        | `ghostwire`        | Port QUIC implementation, layer in HTTP3, IPv6, DNS support |
| `zledger`      | `keystone`         | Rebuild as `keystone` with updated transaction/state engine |

---

## ✅ Tasks by Module

### `ghostcipher`
- [ ] Move `zcrypto` into `ghostcipher/zcrypto`
- [ ] Move `zsig` into `ghostcipher/zsig`
- [ ] Ensure common interfaces for keypair, sign, verify, encrypt, decrypt
- [ ] Optional: create `pqcrypto` and `zk` directories for future primitives

### `sigil`
- [ ] Replace `realid` with `sigil`
- [ ] Migrate GID/QID/DID logic
- [ ] Add Ghostchain ID resolution layer
- [ ] Integrate identity auth hooks for `shadowcraft` and `guardian`

### `zns`
- [ ] Copy existing ZNS protocol (registry, resolution)
- [ ] Ensure support for `.ghost`, `.bc`, `.gcc`, `.gman`, `.spirit` (found in domains.md)
- [ ] Implement DNS Resolver for  .ghost TLD's 
- [ ] Wire into `sigil` for GID-aware resolution
- [ ] Review ZNS_*.md files theres 3 for schema etc. 

### `ghostwire`
- [ ] Move `zquic` implementation here
- [ ] Add HTTP/3 support
- [ ] Add DNS resolver override + client resolver
- [ ] Prepare for IPv6-first networking layer
- [ ] Abstract QUIC as primary transport
- [ ] Add secure tunnel system for Web2 ↔ Web5 communication

### `keystone`
- [ ] Replace `zledger` with redesigned ledger/state engine
- [ ] Implement transaction queue, validation hooks
- [ ] Link to `covenant` and `guardian` for programmable rulesets

---

## 🗂 Directory Structure Plan

```plaintext
shroud/
├── ghostcipher/
│   ├── zcrypto/
│   └── zsig/
├── sigil/
├── zns/
├── ghostwire/
│   └── zquic/
├── keystone/
├── guardian/
├── covenant/
├── shadowcraft/
├── archived/     <-- contains original z* repos
│   ├── zcrypto/
│   ├── zsig/
│   ├── zledger/
│   ├── zquic/
│   ├── zns/
│   └── realid/

🧠 Notes

    Keep archived/ directory clean for legacy reference only.

    Use ClaudeCode to refactor each crate into its new module with cleaner Zig idioms.

    zns TLDs list can be maintained in domains.md.



