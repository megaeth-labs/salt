#[derive(Clone, Copy, Debug)]
pub(crate) struct PrecompTableConfig {
    pub(crate) window_size: usize,
    pub(crate) win_num: usize,
    pub(crate) inner_length: usize,
}

#[cfg(not(zkvm_riscv32_backend))]
mod generic;

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(zkvm_riscv32_backend)]
mod zkvm_riscv32;

#[cfg(not(zkvm_riscv32_backend))]
use self::generic as platform_impl;
#[cfg(zkvm_riscv32_backend)]
use self::zkvm_riscv32 as platform_impl;

pub use platform_impl::multi_scalar_mul;
pub(crate) use platform_impl::{build_precomp_table, msm_bigint_wnaf, projective_zero};
#[cfg(test)]
pub(crate) use platform_impl::batch_proj_to_affine;

#[cfg(all(not(zkvm_riscv32_backend), target_arch = "x86_64"))]
pub(crate) use self::x86_64::add_affine_point;
#[cfg(all(not(zkvm_riscv32_backend), not(target_arch = "x86_64")))]
pub(crate) use self::generic::add_affine_point;
#[cfg(zkvm_riscv32_backend)]
pub(crate) use self::zkvm_riscv32::add_affine_point;
