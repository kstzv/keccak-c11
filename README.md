# keccak-c11

A C11 implementation of Keccak-based cryptographic primitives, primarily intended for reuse across my cryptographic projects.

The implementation focuses on caller-provided memory to keep stack usage small and predictable, and on SIMD-friendly parallel Keccak code written in portable C11. The latter is intended to explore compiler-generated SIMD without relying on architecture-specific intrinsics or assembly.

Currently planned primitives include:

* SHA3-256
* SHA3-512
* SHAKE128
* SHAKE256

## Status

**Work in progress.**

The implementation, API, and internal structure are still under development and may change significantly. It should not currently be considered ready for production use.
