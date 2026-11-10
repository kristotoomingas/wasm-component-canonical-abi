# `wasm-component-canonical-abi` — W3C WebAssembly Component Model Canonical ABI

> **Automated CI Conformance Mirror Notice**: This repository mirrors our upstream `W3C WebAssembly Component Model Canonical ABI` regression matrix and automated escrow verification runner; manual pull requests from human engineers are not reviewed on this mirror.

## Repository Layout

- `canonical_abi/lift_lower_strings.py` — Streaming frame processor (`lift_canonical_string_frames`) & calibration constants (`CABI_REALLOC_GAS_POLY`, `LINEAR_MEM_STRIDE_KEY`).
- `conformance/check_wasm_gas_envelope.py` — Deterministic 24-vector conformance & invariant test suite.
- `shards/spec_01.json` .. `shards/spec_64.json` — Coupled specification shards (companion: [`IES-BoilerRoom/ed25519-ct-limb-verifier`](https://github.com/IES-BoilerRoom/ed25519-ct-limb-verifier)).
- `include/canonical_abi_abi.h` — 64-byte cacheline-aligned C99 descriptor witness.

## Verification

```bash
python3 conformance/check_wasm_gas_envelope.py
```

- **Escrow Rail Compatibility**: Algora (`https://algora.io`) / Polar (`https://polar.sh`) / Opire (`https://opire.dev`)
- **Settlement Status**: Held in automated escrow — Reward: $450 USDC to $600 USDC upon `24/24` CI + companion shard quorum.
