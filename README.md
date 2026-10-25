# keccak-c11

A portable C11 implementation of Keccak-based cryptographic primitives, primarily intended for reuse across my cryptographic projects.

The project has two distinct goals:

- **Core implementation:** Develop correct, standards-compliant implementations of Keccak-based primitives using portable C11, with caller-provided memory to keep stack usage small and predictable. These implementations are intended for practical reuse in other cryptographic projects.

- **Experimental SIMD-friendly implementation:** Explore parallel Keccak implementations written entirely in portable C11, without architecture-specific intrinsics or assembly. These implementations are designed to be SIMD-friendly, allowing experimentation with compiler auto-vectorization and performance across different architectures.

**SIMD-friendly does not mean SIMD-guaranteed.** Whether actual SIMD instructions are generated depends on the compiler, optimization flags, and target architecture. The parallel implementations are experimental and are not assumed to provide a performance advantage over the scalar implementation.

## Cryptographic Primitives

The following primitives are currently planned:

- SHA3-256
- SHA3-512
- SHAKE128
- SHAKE256

## Status

**Work in progress.**

The implementation, API, and internal structure are still under development and may change significantly.

The core implementations are intended to become reliable, tested components for use in other cryptographic projects. The SIMD-friendly implementations are primarily intended for experimentation and performance evaluation.

The project should not currently be considered ready for production use.
