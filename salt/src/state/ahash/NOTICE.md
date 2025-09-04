# Third Party Attribution

## AHash Crate

**Source**: [ahash v0.8.12](https://github.com/tkaitchuck/aHash)
**License**: Apache License 2.0
**Copyright**: Copyright (c) 2019 Tom Kaitchuck
**Repository**: https://github.com/tkaitchuck/aHash

### Files Derived from AHash

- `convert.rs` - Extracted from `src/convert.rs`
- `fallback.rs` - Derived from `src/fallback_hash.rs` and related modules

### Modifications Made

The code has been extracted and modified for deterministic cross-platform behavior:

1. **Deterministic algorithm selection**: Always uses the fallback "folded multiply" algorithm with true 128-bit multiplication instead of platform-specific optimizations
2. **Fixed seeds**: Uses predetermined seeds rather than random generation for reproducible results
3. **Consensus compatibility**: Ensures identical hash values across all platforms and architectures
4. **Module structure**: Reorganized into separate modules for better maintainability

### Original License

The original AHash crate is licensed under the Apache License 2.0. The full license text can be found at:
https://www.apache.org/licenses/LICENSE-2.0