# ✅ TODO: Shroud vNext (Rebuild & Focus Pass)

## 🧱 Core Goals

- [x] Reposition Shroud as **identity & privacy** framework (zero-trust centric)
- [x] Archive legacy experiments (ghostcipher, ghostwire, etc.)
- [ ] Refactor and **integrate Guardian**, not as a full auth stack but as a lightweight policy module
- [ ] Reuse logic from **Sigil** (token generation, ephemeral crypto ops)
- [ ] Optionally migrate **Shadowcraft** constructs into `identity.zig` if delegation logic is reusable

---

## 🔍 Refactoring Plan

### 🧠 Guardian
- [x] Move `Permission`, `Role`, `GuardianError` into `src/guardian.zig`
- [ ] Normalize permission API (`canAccess`, `validateRole`, etc.)
- [ ] Remove unused internal policy layers (only RBAC and contract-level)

### 🧾 Sigil
- [ ] Extract signature + key logic (keep ephemeral signing, ditch monolith)
- [ ] Integrate into `access_token.zig` for token-bound permissions
- [ ] Ensure detached verification mode (compatible with off-chain)

### 🕳️ Shadowcraft
- [ ] Identify any reusable delegation structures
- [ ] Remove UI logic, focus on core delegation trees and contract graphs

---

## 📂 Archive Plan

Move the following to `/archive/` and freeze:
- [x] `ghostcipher/` – obsolete encryption stack
- [x] `ghostwire/` – unused network messaging
- [x] `shadowcraft/` – partially reusable, split before archive
- [x] `sigil/` – source of token/crypto code, keep minimal references
- [ ] `guardian/` – keep minimal form in `src/guardian.zig`, archive rest

---

## 🔌 Integration Targets

- [ ] Plug into Keystone as identity/auth module
- [ ] Emit ZNS-compatible DIDs
- [ ] Validate token-based access at runtime inside ZVM
- [ ] Add stub support for zkProof-based identity attestations

---

## 🧪 Tests

- [ ] guardian_test.zig – permission check, role inheritance
- [ ] identity_test.zig – ephemeral key gen, signing, delegation
- [ ] token_test.zig – issue/validate/expire

---

## ✨ Future Goals

- [ ] Add `AccessContract` abstraction
- [ ] WASM-friendly validator runtime
- [ ] Crypto-agnostic design (pluggable sig providers)
- [ ] zkID compatibility mode

---

## 🔐 Reminder

> Shroud is **not** storage, **not** a runtime, **not** a ledger.
> It's a *trust validator*, *token issuer*, and *permission gate* — nothing more.


