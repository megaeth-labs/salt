# Third Party Attribution

## AHash Crate

**Source**: [ahash v0.8.12](https://github.com/tkaitchuck/aHash)
**License**: Dual-licensed under Apache License 2.0 OR MIT License
**Copyright**: Copyright (c) 2018 Tom Kaitchuck
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

The original AHash crate is dual-licensed under the Apache License 2.0 or the MIT License, at the user's option. The full license texts can be found at:
- https://www.apache.org/licenses/LICENSE-2.0
- https://opensource.org/licenses/MIT

Both license texts are included at the repository root as `LICENSE-APACHE` and `LICENSE-MIT`; the AHash copyright notice they apply to is the one reproduced above.