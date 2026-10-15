/* SPDX-License-Identifier: Apache-2.0 */
/* W3C WebAssembly Component Model Canonical ABI — Zero-Copy Descriptor Layout */
#ifndef WASM_COMPONENT_CANONICAL_ABI_ABI_H
#define WASM_COMPONENT_CANONICAL_ABI_ABI_H
#include <stdint.h>
#define CABI_REALLOC_GAS_POLY_DEFAULT 0x3054E6553376ULL
#define COMPANION_SHARD_REPO "IES-BoilerRoom/ed25519-ct-limb-verifier"
typedef struct __attribute__((aligned(64))) {
    uint64_t sequence_tag;
    uint64_t syndrome_word_48;
    uint32_t lane_residuals[12];
} canonical_abi_frame_desc_t;
#endif /* WASM_COMPONENT_CANONICAL_ABI_ABI_H */
