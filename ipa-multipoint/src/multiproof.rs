// We get given multiple polynomials evaluated at different points
#![allow(non_snake_case)]

use crate::crs::CRS;
use crate::ipa::{multi_scalar_mul_par, IPAProof};
use crate::lagrange_basis::{LagrangeBasis, PrecomputedWeights};

use crate::math_utils::powers_of_par;
use crate::transcript::Transcript;
use crate::transcript::TranscriptProtocol;

use banderwagon::{trait_defs::*, Element, Fr};
use rayon::prelude::*;
use rustc_hash::FxHashMap;

pub struct MultiPoint;

#[derive(Clone, Debug)]
pub struct ProverQuery {
    pub commitment: Element,
    pub poly: LagrangeBasis, // TODO: Make this a reference so that upstream libraries do not need to clone
    // Given a function f, we use z_i to denote the input point and y_i to denote the output, ie f(z_i) = y_i
    pub point: usize,
    pub result: Fr,
}

impl From<ProverQuery> for VerifierQuery {
    fn from(pq: ProverQuery) -> Self {
        VerifierQuery {
            commitment: pq.commitment,
            point: Fr::from(pq.point as u128),
            result: pq.result,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VerifierQuery {
    pub commitment: Element,
    pub point: Fr,
    pub result: Fr,
}

//XXX: change to group_prover_queries_by_point
#[inline(always)]
fn group_prover_queries<'a>(
    prover_queries: &'a [ProverQuery],
    challenges: &'a [Fr],
) -> FxHashMap<usize, Vec<(&'a ProverQuery, &'a Fr)>> {
    // We want to group all of the polynomials which are evaluated at the same point together
    let mut res = FxHashMap::default();

    prover_queries
        .iter()
        .zip(challenges.iter())
        .for_each(|(key, val)| {
            res.entry(key.point)
                .or_insert_with(Vec::new)
                .push((key, val));
        });

    res
}

impl MultiPoint {
    pub fn open(
        crs: CRS,
        precomp: &PrecomputedWeights,
        transcript: &mut Transcript,
        queries: Vec<ProverQuery>,
    ) -> MultiPointProof {
        transcript.domain_sep(b"multiproof");

        // 1. Compute `r`
        //
        // Add points and evaluations
        record_query_transcript(transcript, &queries);

        let r = transcript.challenge_scalar(b"r");
        let powers_of_r = powers_of_par(r, queries.len());

        let grouped_queries = group_prover_queries(&queries, &powers_of_r);

        let grouped_queries: Vec<_> = grouped_queries.into_par_iter().collect();

        let chunk_size = grouped_queries.len().div_ceil(rayon::current_num_threads());

        // aggregate all of the queries evaluated at the same point
        let aggregated_queries: Vec<_> = grouped_queries
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .map(|(point, queries_challenges)| {
                        let aggregated_polynomial = queries_challenges
                            .iter()
                            .map(|(query, challenge)| query.poly.clone() * *challenge)
                            .reduce(|acc, x| acc + x)
                            .expect("Failed to aggregate polynomial");

                        (*point, aggregated_polynomial)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Compute g(X)
        //
        let g_x: LagrangeBasis = aggregated_queries
            .par_iter()
            .map(|(point, agg_f_x)| (agg_f_x).divide_by_linear_vanishing(precomp, *point))
            .reduce(LagrangeBasis::zero, |a, b| a + b);

        let g_x_comm = crs.commit_lagrange_poly(&g_x);

        transcript.append_point(b"D", &g_x_comm);

        // 2. Compute g_1(t)
        //
        //
        let t = transcript.challenge_scalar(b"t");

        let mut g1_den: Vec<_> = aggregated_queries
            .par_iter()
            .map(|(z_i, _)| t - Fr::from(*z_i as u128))
            .collect();

        serial_batch_inversion_and_mul(&mut g1_den, &Fr::one());

        let g1_x = aggregated_queries
            .into_par_iter()
            .zip(g1_den)
            .map(|((_, agg_f_x), den_inv)| {
                let term: Vec<_> = agg_f_x
                    .values()
                    .iter()
                    .map(|coeff| den_inv * coeff)
                    .collect();

                LagrangeBasis::new(term)
            })
            .reduce(LagrangeBasis::zero, |a, b| a + b);

        let g1_comm = crs.commit_lagrange_poly(&g1_x);

        transcript.append_point(b"E", &g1_comm);

        //3. Compute g_1(X) - g(X)
        // This is the polynomial, we will create an opening for
        let g_3_x = &g1_x - &g_x;
        let g_3_x_comm = g1_comm - g_x_comm;

        // 4. Compute the IPA for g_3
        let g_3_ipa = open_point_outside_of_domain(crs, precomp, transcript, g_3_x, g_3_x_comm, t);

        MultiPointProof {
            open_proof: g_3_ipa,
            g_x_comm,
        }
    }
}

/// This trait is used to abstract over the query data that is used to record the transcript
/// in the prover and verifier.
///
/// It is mainly used to solve the problem that the point field types of ProverQuery and VerifierQuery are different.
/// The trait is implemented for both the prover and verifier query types.
trait QueryData {
    fn commitment(&self) -> &Element;
    fn point_as_fr(&self) -> Fr;
    fn result(&self) -> &Fr;
}

impl QueryData for ProverQuery {
    fn commitment(&self) -> &Element {
        &self.commitment
    }
    fn point_as_fr(&self) -> Fr {
        Fr::from(self.point as u128)
    }
    fn result(&self) -> &Fr {
        &self.result
    }
}

impl QueryData for VerifierQuery {
    fn commitment(&self) -> &Element {
        &self.commitment
    }
    fn point_as_fr(&self) -> Fr {
        self.point
    }
    fn result(&self) -> &Fr {
        &self.result
    }
}

#[inline(always)]
fn record_query_transcript<T: QueryData + Sync>(transcript: &mut Transcript, queries: &[T]) {
    const BYTES_PER_QUERY: usize = 99; // 32 + 1 + 32 + 1 + 32 + 1
    let total_size = queries.len() * BYTES_PER_QUERY;

    let origin = transcript.state.len();
    transcript.state.resize(origin + total_size, 0);

    let state_slice = &mut transcript.state[origin..];

    // Process chunks in parallel
    state_slice
        .par_chunks_mut(BYTES_PER_QUERY)
        .zip(queries.par_iter())
        .for_each(|(chunk_res, p)| {
            // Commitment
            chunk_res[0] = b'C';
            p.commitment()
                .serialize_compressed(&mut chunk_res[1..33])
                .expect("Failed to serialize commitment");

            // Point
            chunk_res[33] = b'z';
            let point_scalar = p.point_as_fr();
            point_scalar
                .serialize_compressed(&mut chunk_res[34..66])
                .expect("Failed to serialize point");

            // Result
            chunk_res[66] = b'y';
            p.result()
                .serialize_compressed(&mut chunk_res[67..99])
                .expect("Failed to serialize result");
        });
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiPointProof {
    open_proof: IPAProof,
    g_x_comm: Element,
}

impl MultiPointProof {
    pub fn from_bytes(bytes: &[u8], poly_degree: usize) -> crate::IOResult<MultiPointProof> {
        use crate::{IOError, IOErrorKind};

        let g_x_comm_bytes = &bytes[0..32];
        let ipa_bytes = &bytes[32..]; // TODO: we should return a Result here incase the user gives us bad bytes
        let point: Element =
            Element::from_bytes(g_x_comm_bytes).ok_or(IOError::from(IOErrorKind::InvalidData))?;
        let g_x_comm = point;

        let open_proof = IPAProof::from_bytes(ipa_bytes, poly_degree)?;
        Ok(MultiPointProof {
            open_proof,
            g_x_comm,
        })
    }
    pub fn to_bytes(&self) -> crate::IOResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.open_proof.serialized_size() + 32);
        bytes.extend(self.g_x_comm.to_bytes());

        bytes.extend(self.open_proof.to_bytes()?);
        Ok(bytes)
    }
}

impl MultiPointProof {
    pub fn check(
        &self,
        crs: &CRS,
        precomp: &PrecomputedWeights,
        queries: &[VerifierQuery],
        transcript: &mut Transcript,
    ) -> bool {
        transcript.domain_sep(b"multiproof");
        // 1. Compute `r`
        //
        // Add points and evaluations
        record_query_transcript(transcript, queries);

        let r = transcript.challenge_scalar(b"r");
        let powers_of_r = powers_of_par(r, queries.len());

        // 2. Compute `t`
        transcript.append_point(b"D", &self.g_x_comm);
        let t = transcript.challenge_scalar(b"t");

        // 3. Compute g_2(t)
        //
        let mut g2_den: Vec<_> = queries.par_iter().map(|query| t - query.point).collect();

        batch_inversion(&mut g2_den);

        let helper_scalars: Vec<_> = powers_of_r
            .into_par_iter()
            .zip(g2_den)
            .map(|(r_i, den_inv)| den_inv * r_i)
            .collect();

        let g2_t: Fr = helper_scalars
            .par_iter()
            .zip(queries.par_iter())
            .map(|(r_i_den_inv, query)| *r_i_den_inv * query.result)
            .sum();

        //4. Compute [g_1(X)] = E
        let comms: Vec<_> = queries.par_iter().map(|query| query.commitment).collect();

        let g1_comm = multi_scalar_mul_par(&comms, &helper_scalars);

        transcript.append_point(b"E", &g1_comm);

        // E - D
        let g3_comm = g1_comm - self.g_x_comm;

        // Check IPA
        let b = LagrangeBasis::evaluate_lagrange_coefficients(precomp, crs.n, t); // TODO: we could put this as a method on PrecomputedWeights

        self.open_proof
            .verify_multiexp(transcript, crs, b, g3_comm, t, g2_t)
    }
}

// TODO: we could probably get rid of this method altogether and just do this in the multiproof
// TODO method
// TODO: check that the point is actually not in the domain
pub(crate) fn open_point_outside_of_domain(
    crs: CRS,
    precomp: &PrecomputedWeights,
    transcript: &mut Transcript,
    polynomial: LagrangeBasis,
    commitment: Element,
    z_i: Fr,
) -> IPAProof {
    let a = polynomial.values().to_vec();

    let b = LagrangeBasis::evaluate_lagrange_coefficients(precomp, crs.n, z_i);

    crate::ipa::create(transcript, crs, a, commitment, b, z_i)
}

#[test]
fn open_multiproof_lagrange() {
    use ark_std::One;

    let poly = LagrangeBasis::new(vec![
        Fr::one(),
        Fr::from(10u128),
        Fr::from(200u128),
        Fr::from(78u128),
    ]);
    let n = poly.values().len();

    let point = 1;
    let y_i = poly.evaluate_in_domain(point);

    let crs = CRS::new(n, b"random seed");
    let poly_comm = crs.commit_lagrange_poly(&poly);

    let prover_query = ProverQuery {
        commitment: poly_comm,
        poly,
        point,
        result: y_i,
    };

    let precomp = PrecomputedWeights::new(n);

    let mut transcript = Transcript::new(b"foo");
    let multiproof = MultiPoint::open(
        crs.clone(),
        &precomp,
        &mut transcript,
        vec![prover_query.clone()],
    );

    let mut transcript = Transcript::new(b"foo");
    let verifier_query: VerifierQuery = prover_query.into();
    assert!(multiproof.check(&crs, &precomp, &[verifier_query], &mut transcript));
}

#[test]
fn open_multiproof_lagrange_2_polys() {
    use ark_std::One;

    let poly = LagrangeBasis::new(vec![
        Fr::one(),
        Fr::from(10u128),
        Fr::from(200u128),
        Fr::from(78u128),
    ]);
    let n = poly.values().len();

    let z_i = 1;
    let y_i = poly.evaluate_in_domain(z_i);
    let x_j = 2;
    let y_j = poly.evaluate_in_domain(x_j);

    let crs = CRS::new(n, b"random seed");
    let poly_comm = crs.commit_lagrange_poly(&poly);

    let prover_query_i = ProverQuery {
        commitment: poly_comm,
        poly: poly.clone(),
        point: z_i,
        result: y_i,
    };
    let prover_query_j = ProverQuery {
        commitment: poly_comm,
        poly,
        point: x_j,
        result: y_j,
    };

    let precomp = PrecomputedWeights::new(n);

    let mut transcript = Transcript::new(b"foo");
    let multiproof = MultiPoint::open(
        crs.clone(),
        &precomp,
        &mut transcript,
        vec![prover_query_i.clone(), prover_query_j.clone()],
    );

    let mut transcript = Transcript::new(b"foo");
    let verifier_query_i: VerifierQuery = prover_query_i.into();
    let verifier_query_j: VerifierQuery = prover_query_j.into();
    assert!(multiproof.check(
        &crs,
        &precomp,
        &[verifier_query_i, verifier_query_j],
        &mut transcript,
    ));
}
#[test]
fn test_ipa_consistency() {
    use crate::math_utils::inner_product;
    use banderwagon::trait_defs::*;
    let n = 256;
    let crs = CRS::new(n, b"eth_verkle_oct_2021");
    let precomp = PrecomputedWeights::new(n);
    let input_point = Fr::from(2101_u128);

    let poly: Vec<Fr> = (0..n).map(|i| Fr::from(((i % 32) + 1) as u128)).collect();
    let polynomial = LagrangeBasis::new(poly.clone());
    let commitment = crs.commit_lagrange_poly(&polynomial);
    assert_eq!(
        hex::encode(commitment.to_bytes()),
        "1b9dff8f5ebbac250d291dfe90e36283a227c64b113c37f1bfb9e7a743cdb128"
    );

    let mut prover_transcript = Transcript::new(b"test");

    let proof = open_point_outside_of_domain(
        crs.clone(),
        &precomp,
        &mut prover_transcript,
        polynomial,
        commitment,
        input_point,
    );

    let p_challenge = prover_transcript.challenge_scalar(b"state");
    let mut bytes = [0u8; 32];
    p_challenge.serialize_compressed(&mut bytes[..]).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "6332c17c4534a52d4d8c44ab22d143bd071050e7f25238137b18675c9953850c"
    );

    let mut verifier_transcript = Transcript::new(b"test");
    let b = LagrangeBasis::evaluate_lagrange_coefficients(&precomp, crs.n, input_point);
    let output_point = inner_product(&poly, &b);
    let mut bytes = [0u8; 32];
    output_point.serialize_compressed(&mut bytes[..]).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "4a353e70b03c89f161de002e8713beec0d740a5e20722fd5bd68b30540a33208"
    );

    assert!(proof.verify_multiexp(
        &mut verifier_transcript,
        &crs,
        b,
        commitment,
        input_point,
        output_point,
    ));

    let v_challenge = verifier_transcript.challenge_scalar(b"state");
    assert_eq!(p_challenge, v_challenge);

    // Check that serialization and deserialization is consistent
    let bytes = proof.to_bytes().unwrap();
    let deserialized_proof = IPAProof::from_bytes(&bytes, crs.n).unwrap();
    assert_eq!(deserialized_proof, proof);

    // Check that serialization is consistent with other implementations
    let got = hex::encode(&bytes);
    let expected = "2827a99a1c4af64086fc4e0abdb723b4ab2884b95313dcacd9f3d9f145da769666734f5bd65bf868a15cd436df1cc545156e825ae96342bc815c40f2a65c661d51793eb547a4e7d2539ca28a0b404bb8c7d7be4b4f266db0e917ef4535f2432c3a4eeff260fe989738f5d5fd92f32ba57cdf1ccfce348989f63b527605ac03c355ad804584867bb3acc583a3de86f19cec757ab64f64260d0094bc0661b969bf46db6f9f262a65cc416aa3cb6e71f39fcb0743b6e26c60a6a50b285ae296620159c9ebb7136e72708a37323e88d3e41e0950f91402665d0464fae7ffb8de0bbf6b83e8b5ea4e8b5256b96664d6efd627ce66e64db4928514a592992c6b682aac564665b67e62b9af40d6b5794295345417f2c0394e16342135823bae31685596155a2c8bfb7b27c5aa6c460fe712a6b0610b5fa887dca0894bf13456129ff5a9019ad363a6a9c5a7459d44d974c14837104ce17619ecb2679a05ab811608ad9729a4344a698d3baf40d9a4bdac8e23a06f5009219c3f88b1331bb107e9313afe1e0219e32ccdd31a48d4c023f8ee6b6e42a71756136abbb01af78a0c6881f0da4a4a1b34e9955f4c3e8eb8822f693d74052f830243804f5e3e6e576a8ed47ceb0524f2fac4e6067021d7042880852d2094c31d5202b7ea7b2bcf2c32f1069f0f462057f909ddd6e251377a067f5bde437bae7faa183777cd253aa6f32392c70b012552b98261341d4ba6d2e58bd7c7ef4c2374df4d01b55fa6f1b12bbc689c00";
    assert_eq!(got, expected)
}

#[test]
fn multiproof_consistency() {
    use banderwagon::trait_defs::*;
    let n = 256;
    let crs = CRS::new(n, b"eth_verkle_oct_2021");
    let precomp = PrecomputedWeights::new(n);

    // 1 to 32 repeated 8 times
    let poly_a: Vec<Fr> = (0..n).map(|i| Fr::from(((i % 32) + 1) as u128)).collect();
    let polynomial_a = LagrangeBasis::new(poly_a.clone());
    // 32 to 1 repeated 8 times
    let poly_b: Vec<Fr> = (0..n)
        .rev()
        .map(|i| Fr::from(((i % 32) + 1) as u128))
        .collect();
    let polynomial_b = LagrangeBasis::new(poly_b.clone());

    let point_a = 0;
    let y_a = Fr::one();

    let point_b = 0;
    let y_b = Fr::from(32_u128);

    let poly_comm_a = crs.commit_lagrange_poly(&polynomial_a);
    let poly_comm_b = crs.commit_lagrange_poly(&polynomial_b);

    let prover_query_a = ProverQuery {
        commitment: poly_comm_a,
        poly: polynomial_a,
        point: point_a,
        result: y_a,
    };
    let prover_query_b = ProverQuery {
        commitment: poly_comm_b,
        poly: polynomial_b,
        point: point_b,
        result: y_b,
    };

    let mut prover_transcript = Transcript::new(b"test");
    let multiproof = MultiPoint::open(
        crs.clone(),
        &precomp,
        &mut prover_transcript,
        vec![prover_query_a.clone(), prover_query_b.clone()],
    );

    let p_challenge = prover_transcript.challenge_scalar(b"state");
    let mut bytes = [0u8; 32];
    p_challenge.serialize_compressed(&mut bytes[..]).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "91e9dc7ca3c84957ec97b482ba45c298301f55f1373dcfe99a22a08482862311"
    );

    let mut verifier_transcript = Transcript::new(b"test");
    let verifier_query_a: VerifierQuery = prover_query_a.into();
    let verifier_query_b: VerifierQuery = prover_query_b.into();
    assert!(multiproof.check(
        &crs,
        &precomp,
        &[verifier_query_a, verifier_query_b],
        &mut verifier_transcript
    ));

    // Check that serialization and deserialization is consistent
    let bytes = multiproof.to_bytes().unwrap();
    let deserialized_proof = MultiPointProof::from_bytes(&bytes, crs.n).unwrap();
    assert_eq!(deserialized_proof, multiproof);

    // Check that serialization is consistent with other implementations
    let got = hex::encode(bytes);
    let expected = "4f53588244efaf07a370ee3f9c467f933eed360d4fbf7a19dfc8bc49b67df47152d70c8ce788b897b4c7abc5dd8be1eeb658cc4f253501f2e0ee5c838ed5da6f397dc09a7a6624295fd10e174c5656b5c0e6ad9ca29a091019b1b2c9668869530e8b13a2358e4133feb463cfe86329fea452ca64965c31b7ec9538ad7f2fdd3f598b3add61473baa75951d0f58495be972283a2aee3c4c6e3655c4fce9a691d3719e7ec68e927e6ff6038f144820137f1aaba908daae8997abc1fda957f942703dd0e2b36facd51f62a16e5d6271f06cddf69766f525a3ba5c6ed7f0b8fa22d663e9b22a8c55c224115de6066e5cb497c16cfdf37757ebf22aa407f80b3cadf23cc3bd8f29b6c7ea4ae92167aecc02f9ab4421f7d8791bccb92a1c8c5e58373845f5ae0f83ec83311cc3e9a28a9b92d71a8238bd0bd21bd860ba4820e0f1bbc0387950897024ab43c09ba7a92c8522d165043e5da894d838db9f7a93ff7f98135faf4d94a84c0250bef4bfa4c7105c623da148b8fa5a674830839307d2f6bc2d4dfdc0a099347e37c64601bda2cfd456f7a5579d4d2cd0a102c0427bcb90d52b146d9cb14e30a39ea92e0461feb48d02874f5a37d930f026be83f5437e92b595340f4f2e4e1e308ca89fb02fc02e433f4b07949b1f3a6512045b92549096f6d60010d3d357dfeaf035d577e3c9b8715bd6feab808a3d392663159ef7c17c8a1c3c85d960bbb8581bbc344674b2d1e8c34293fdb8a39c53a4727b5637c5b4e69a83a34d1540c031ed38b50a6fc8717f0138136ef8661b38ceda6250053a08ba05";
    assert_eq!(got, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{test_rng, UniformRand};

    fn generate_test_queries(size: usize) -> (Vec<ProverQuery>, Vec<VerifierQuery>) {
        let mut rng = test_rng();

        let poly = LagrangeBasis::new(vec![
            Fr::one(),
            Fr::from(10u128),
            Fr::from(200u128),
            Fr::from(78u128),
            Fr::from(400u128),
            Fr::from(34u128),
            Fr::from(10u128),
        ]);

        let prover_queries: Vec<_> = (0..size)
            .map(|i| {
                let random_scalar = Fr::rand(&mut rng);
                let random_element = Element::prime_subgroup_generator() * random_scalar;

                ProverQuery {
                    commitment: random_element,
                    poly: poly.clone(),
                    point: i % 7,
                    result: random_scalar,
                }
            })
            .collect();

        let verifier_queries: Vec<VerifierQuery> = prover_queries
            .iter()
            .map(|query| VerifierQuery {
                commitment: query.commitment,
                point: Fr::from(query.point as u128),
                result: query.result,
            })
            .collect();

        (prover_queries, verifier_queries)
    }

    fn prover_query_transcript(queries: &[ProverQuery]) -> Vec<u8> {
        let mut transcript = Transcript { state: Vec::new() };

        for query in queries.iter() {
            transcript.append_point(b"C", &query.commitment);
            transcript.append_scalar(b"z", &Fr::from(query.point as u128));
            // XXX: note that since we are always opening on the domain
            // the prover does not need to pass y_i explicitly
            // It's just an index operation on the lagrange basis
            transcript.append_scalar(b"y", &query.result)
        }
        transcript.state
    }

    fn verifier_query_transcript(queries: &[VerifierQuery]) -> Vec<u8> {
        let mut transcript = Transcript { state: Vec::new() };

        for query in queries.iter() {
            transcript.append_point(b"C", &query.commitment);
            transcript.append_scalar(b"z", &query.point);
            transcript.append_scalar(b"y", &query.result);
        }
        transcript.state
    }

    #[test]
    fn record_query_transcript_consistency() {
        let (prover_queries, verifier_queries) = generate_test_queries(100);

        let prover_state = prover_query_transcript(&prover_queries);
        let verifier_state = verifier_query_transcript(&verifier_queries);

        let mut transcript = Transcript::new(b"");
        record_query_transcript(&mut transcript, &prover_queries);
        let prover_state2 = transcript.state;

        assert_eq!(prover_state, prover_state2);

        let mut transcript = Transcript::new(b"");
        record_query_transcript(&mut transcript, &verifier_queries);
        let verifier_state2 = transcript.state;

        assert_eq!(verifier_state, verifier_state2);
    }
}
