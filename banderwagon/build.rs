use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        zkvm_riscv32: { all(target_os = "zkvm", target_arch = "riscv32") },
        zkvm_riscv32_backend: { any(all(target_os = "zkvm", target_arch = "riscv32"), feature = "zkvm-riscv32-sim") },
    }
}
