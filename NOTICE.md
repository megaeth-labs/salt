# NOTICE

This file contains attributions and notices for third-party code incorporated into this project, as required by the respective licenses.

---

## Third-Party Components

### 1. rust-verkle (Banderwagon and IPA-Multipoint)

This project includes modified portions of code from the rust-verkle project.

**Copyright**: Copyright (c) 2023 rust-verkle contributors  
**Source Repository**: https://github.com/crate-crypto/rust-verkle  
**License**: Dual-licensed under Apache License 2.0 OR MIT License  
**Components Derived**:
- `banderwagon/` - Banderwagon elliptic curve cryptography implementation
- `ipa-multipoint/` - Inner Product Argument (IPA) based polynomial commitment scheme with multipoint opening proofs

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

The original rust-verkle code is dual-licensed under:
- Apache License, Version 2.0 ([full text](https://www.apache.org/licenses/LICENSE-2.0))
- MIT License ([full text](https://opensource.org/licenses/MIT))

Both license texts are included in this repository as `LICENSE-APACHE` and `LICENSE-MIT`.

---

## Additional Notices

For component-specific notices, please refer to individual NOTICE.md files within subdirectories:
- `salt/src/state/ahash/NOTICE.md` - Attribution for ahash implementation components
