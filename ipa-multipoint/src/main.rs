use banderwagon::{salt_committer::Committer, trait_defs::*, Fr};
use ipa_multipoint::crs::CRS;
use std::time::Instant;

#[allow(clippy::needless_range_loop)]
fn main() {
    println!("Benchmarking Pedersen hashing...");
    const N: usize = 5000;

    let crs = CRS::new(256, "eth_verkle_oct_2021".as_bytes());

    let committer = Committer::new(&crs.G, 11);
    let mut vec_len = 1;
    while vec_len <= 256 {
        println!("\twith {vec_len} elements... ");

        let mut vecs = vec![[Fr::from(0u128); 256]; N];
        for (i, vecs_i) in vecs.iter_mut().enumerate() {
            for j in 0..vec_len {
                vecs_i[j] = Fr::from((i + j + 0x424242) as u128);
            }
            for j in vec_len..vecs_i.len() {
                vecs_i[j] = Fr::zero();
            }
        }

        let start = Instant::now();
        for i in 0..N {
            for (idx, v) in vecs[i][0..vec_len].iter().enumerate() {
                committer.mul_index(v, idx);
            }
        }
        let duration = start.elapsed();
        println!("takes {}µs", duration.as_micros() / (N as u128));

        vec_len <<= 1;
    }
}
