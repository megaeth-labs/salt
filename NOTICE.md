# NOTICE

This file contains attributions and notices for third-party code incorporated into this project, as required by the respective licenses.

---

## Third-Party Components

### 1. rust-verkle (Banderwagon and IPA-Multipoint)

This project includes modified portions of code from the rust-verkle project.

**Source Repository**: https://github.com/crate-crypto/rust-verkle  
**Components Derived**:
- `banderwagon/` - Banderwagon elliptic curve cryptography implementation
- `ipa-multipoint/` - Inner Product Argument (IPA) based polynomial commitment scheme with multipoint opening proofs

| Component | Origin | Copyright | License in this repository |
|---|---|---|---|
| `banderwagon/` | rust-verkle `banderwagon/`, first published as [crate-crypto/banderwagon](https://github.com/crate-crypto/banderwagon) (Apache-2.0) | Copyright (c) 2023 Crate Crypto | MIT OR Apache-2.0 |
| `ipa-multipoint/` | rust-verkle `ipa-multipoint/`, first published as [crate-crypto/ipa_multipoint](https://github.com/crate-crypto/ipa_multipoint) (MIT) | Copyright (c) 2021 Kevaundray Wedderburn; Copyright (c) 2023 Crate Crypto | MIT |

#### Modifications

This project has modified the original rust-verkle code. Key modifications include:

- **Cryptographic Parameters**: Updated Common Reference String (CRS) generation seed and corresponding 257-point generator values for domain-specific requirements
- **Performance Optimizations**: 
  - Integrated Rayon-based parallelization for multiproof operations
  - Optimized scalar operations and multi-scalar multiplication algorithms
  - Enhanced transcript handling with batch recording methods
- **API Changes**:
  - Made `MultiPointProof` struct fields private for better encapsulation
  - Updated `Element` serialization to return `Result` types for improved error handling
  - Removed uncompressed serialization methods
- **Code Organization**:
  - Consolidated trait implementations into main module files
  - Added domain-specific modules (`salt_committer.rs`, `scalar_multi_asm.rs`)
  - Restructured benchmarking framework
- **Documentation**: Enhanced documentation for Twisted Edwards curve operations and Lagrange basis implementations

#### License Compliance

rust-verkle offers its code under the MIT License or the Apache License, Version 2.0: its README states "MIT/APACHE" and its repository root carries both license texts.

- `banderwagon/` has no license file of its own in rust-verkle, so the repository-level MIT OR Apache-2.0 terms apply to it. This project distributes it under the same terms; the license texts are `banderwagon/LICENSE-MIT` and `banderwagon/LICENSE-APACHE`.
- `ipa-multipoint/` keeps, in rust-verkle, the MIT license file of the repository it was first published in. That file is the more specific grant, so this project distributes `ipa-multipoint/` under the MIT License only; the license text is `ipa-multipoint/LICENSE`.

---

## Additional Notices

For component-specific notices, please refer to individual NOTICE.md files within subdirectories:
- `salt/src/state/ahash/NOTICE.md` - Attribution for ahash implementation components
