//! Macros for configuration options

/// Returns the number of threads to use.
/// Uses `rayon::current_num_threads()` if the "parallel" feature is enabled, otherwise returns 1.
#[macro_export]
macro_rules! num_threads {
    () => {{
        #[cfg(feature = "parallel")]
        {
            rayon::current_num_threads()
        }

        #[cfg(not(feature = "parallel"))]
        {
            1
        }
    }};
}

/// Chooses between parallel and sequential `into_iter`.
/// Uses `into_par_iter()` if the "parallel" feature is enabled, otherwise uses `into_iter()`.
#[macro_export]
macro_rules! use_into_iter {
    ($e: expr) => {{
        #[cfg(feature = "parallel")]
        {
            $e.into_par_iter()
        }

        #[cfg(not(feature = "parallel"))]
        {
            $e.into_iter()
        }
    }};
}

/// Chooses between parallel and sequential `iter`.
/// Uses `par_iter()` if the "parallel" feature is enabled, otherwise uses `iter()`.
#[macro_export]
macro_rules! use_iter {
    ($e: expr) => {{
        #[cfg(feature = "parallel")]
        {
            $e.par_iter()
        }

        #[cfg(not(feature = "parallel"))]
        {
            $e.iter()
        }
    }};
}

/// Chooses between parallel and sequential `chunks_mut`.
/// Uses `par_chunks_mut()` if the "parallel" feature is enabled, otherwise uses `chunks_mut()`.
#[macro_export]
macro_rules! use_chunks_mut {
    ($e: expr, $size: expr) => {{
        #[cfg(feature = "parallel")]
        {$e.par_chunks_mut($size)}

        #[cfg(not(feature = "parallel"))]
        {$e.chunks_mut($size)}
    }};
}

/// Chooses between parallel and sequential `chunks`.
/// Uses `par_chunks()` if the "parallel" feature is enabled, otherwise uses `chunks()`.
#[macro_export]
macro_rules! use_chunks {
    ($e: expr, $size: expr) => {{
        #[cfg(feature = "parallel")]
        {$e.par_chunks($size)}

        #[cfg(not(feature = "parallel"))]
        {$e.chunks($size)}
    }};
}

/// Chooses between parallel and sequential reduction.
/// Uses `reduce()` if the "parallel" feature is enabled, otherwise uses `fold()`.
#[macro_export]
macro_rules! use_reduce {
    ($e: expr, $default: expr, $op: expr) => {{
        #[cfg(feature = "parallel")]
        {
            $e.reduce($default, $op)
        }

        #[cfg(not(feature = "parallel"))]
        {
            $e.fold($default(), $op)
        }
    }};
}

/// Chooses between parallel and sequential unstable sort.
/// Uses `par_sort_unstable()` if the "parallel" feature is enabled, otherwise uses `sort_unstable()`.
#[macro_export]
macro_rules! use_sort_unstable {
    ($e: expr) => {{
        #[cfg(feature = "parallel")]
        {
            $e.par_sort_unstable()
        }

        #[cfg(not(feature = "parallel"))]
        {
            $e.sort_unstable()
        }
    }};
}

/// Chooses between parallel and sequential unstable sort by comparator.
/// Uses `par_sort_unstable_by()` if the "parallel" feature is enabled, otherwise uses `sort_unstable_by()`.
#[macro_export]
macro_rules! use_sort_unstable_by {
    ($e: expr, $op: expr) => {{
        #[cfg(feature = "parallel")]
        {
            $e.par_sort_unstable_by($op)
        }

        #[cfg(not(feature = "parallel"))]
        {
            $e.sort_unstable_by($op)
        }
    }};
}

/// Chooses between parallel and sequential unstable sort by key.
/// Uses `par_sort_unstable_by_key()` if the "parallel" feature is enabled, otherwise uses `sort_unstable_by_key()`.
#[macro_export]
macro_rules! use_sort_unstable_by_key {
    ($e: expr, $op: expr) => {{
        #[cfg(feature = "parallel")]
        {
            $e.par_sort_unstable_by_key($op)
        }

        #[cfg(not(feature = "parallel"))]
        {
            $e.sort_unstable_by_key($op)
        }
    }};
}

#[macro_export]
macro_rules! use_edw_proj_zero {
    () => {{
        #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
        {
            let mut zero = EdwardsProjective::zero();
            zero.y = Fq::zero();
            zero.z = Fq::zero();
            zero.y.0 .0[0] = 1;
            zero.z.0 .0[0] = 1;
            zero
        }

        #[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
        {
            EdwardsProjective::zero()
        }
    }};
}
