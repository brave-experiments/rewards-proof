use bulletproofs::{inner_product, BulletproofGens, LinearProof, PedersenGens, RangeProof};
use core::iter;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::VartimeMultiscalarMul,
};
use merlin::Transcript;
use std::vec;

pub fn rewards_proof_setup(
    incentive_catalog_size: u64,
) -> (Vec<PedersenGens>, Vec<BulletproofGens>) {
    // Generate generators for the range proof
    let (ps_gen, bp_gen) = setup(64);
    // Generate generators for the linear proof
    let (ps_gen_lin, bp_gen_lin) = setup(incentive_catalog_size as usize);

    let pedersen_gens = vec![ps_gen, ps_gen_lin];
    let bulletproof_gens = vec![bp_gen, bp_gen_lin];
    (pedersen_gens, bulletproof_gens)
}

/// Generates proofs and commitments for the entire rewards proof
pub fn rewards_proof_generation(
    pedersen_gens: Vec<PedersenGens>,
    bulletproof_gens: Vec<BulletproofGens>,
    value: u64,
    private_value: Vec<Scalar>,
    public_value: Vec<Scalar>,
    incentive_catalog_size: u64,
) -> (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
) {
    let limit_range_proof: usize = 16; // param?

    // Generate range proof
    let (range_proof, range_proof_commitments) = range_proof(
        &pedersen_gens.first().unwrap(),
        &bulletproof_gens.first().unwrap(),
        value,
        limit_range_proof,
    );

    // Generate linear proof
    let (linear_proof, linear_proof_commitments) = linear_proof(
        &pedersen_gens.last().unwrap(),
        &bulletproof_gens.last().unwrap(),
        private_value.clone(),
        public_value.clone(),
        incentive_catalog_size as usize,
    );

    // convert commitments to byte vectors
    let l_comm = (
        linear_proof_commitments
            .0
            .iter()
            .flat_map(|point| point.compress().to_bytes().to_vec())
            .collect(),
        linear_proof_commitments.1.compress().to_bytes().to_vec(),
        linear_proof_commitments.2.compress().to_bytes().to_vec(),
        linear_proof_commitments.3.to_bytes().to_vec(),
    );

    // Return proofs as byte array + commitements?
    (
        range_proof.to_bytes(),
        linear_proof.to_bytes(),
        range_proof_commitments.to_bytes().to_vec(),
        l_comm,
    )
}

/// Verifies the rewards proofs
pub fn rewards_proof_verification(
    pedersen_gens: &Vec<PedersenGens>,
    bulletproof_gens: &Vec<BulletproofGens>,
    range_proof: Vec<u8>,
    range_proof_commitments: Vec<u8>,
    linear_proof: Vec<u8>,
    public_value: Vec<Scalar>,
    linear_proof_commitments: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
) -> bool {
    let limit_range_proof: usize = 16; // param?

    // Deserialize range proof
    let r_proof = RangeProof::from_bytes(range_proof.as_slice()).unwrap();
    let r_proof_commitments = CompressedRistretto::from_slice(range_proof_commitments.as_slice());

    // Verify range proof
    if !range_verify(
        &pedersen_gens.first().unwrap(),
        &bulletproof_gens.first().unwrap(),
        r_proof,
        r_proof_commitments,
        limit_range_proof,
    ) {
        return false;
    }

    // Deserialise linear proof
    let l_proof = LinearProof::from_bytes(linear_proof.as_slice()).unwrap();
    let g: Vec<RistrettoPoint> = linear_proof_commitments
        .0
        .chunks(CompressedRistretto::default().as_bytes().len())
        .map(|chunk| CompressedRistretto::from_slice(chunk).decompress().unwrap())
        .collect();
    let f = CompressedRistretto::from_slice(linear_proof_commitments.1.as_slice());
    let b = CompressedRistretto::from_slice(linear_proof_commitments.2.as_slice());
    let c = CompressedRistretto::from_slice(linear_proof_commitments.3.as_slice());

    // Verify linear proof
    if !linear_verify(
        l_proof,
        public_value,
        g,
        f.decompress().unwrap(),
        b.decompress().unwrap(),
        c,
    ) {
        return false;
    }

    return true;
}

/// Verifies the rewards proofs
pub fn rewards_proof_verification_multiple(
    pedersen_gens: &Vec<PedersenGens>,
    bulletproof_gens: &Vec<BulletproofGens>,
    range_proof: Vec<Vec<u8>>,
    range_proof_commitments: Vec<Vec<u8>>,
    linear_proof: Vec<Vec<u8>>,
    public_value: Vec<Scalar>,
    linear_proof_commitments: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>,
    number_of_proofs: usize,
) -> bool {
    for i in 0..number_of_proofs {
        // verify individual range proofs
        let result = rewards_proof_verification(
            &pedersen_gens,
            &bulletproof_gens,
            range_proof[i].clone(),
            range_proof_commitments[i].clone(),
            linear_proof[i].clone(),
            public_value.clone(),
            linear_proof_commitments[i].clone(),
        );
        if result == false {
            panic!("Verifying {}'th rewards proof failed!", i);
        }
    }
    return true;
}

/// Setup for Pedersen Generators and BulletProofs Generators
fn setup(gen_capacity: usize) -> (PedersenGens, BulletproofGens) {
    let pedersen_generators = PedersenGens::default();
    let bulletproof_generators = BulletproofGens::new(gen_capacity, 1);
    (pedersen_generators, bulletproof_generators)
}

/// Generates a proof and the commitments for a range proof
fn range_proof(
    ps_gen: &PedersenGens,
    bp_gen: &BulletproofGens,
    value: u64,
    n: usize,
) -> (RangeProof, CompressedRistretto) {
    let mut rng = rand::thread_rng();
    let blinding = Scalar::random(&mut rng);

    let mut prover_transcript = Transcript::new(b"rangeproof");
    let (proof, commitments) = RangeProof::prove_single(
        &bp_gen,
        &ps_gen,
        &mut prover_transcript,
        value,
        &blinding,
        n,
    )
    .expect("Error when creating rangeproof");

    (proof, commitments)
}

/// Verifies a range proof
fn range_verify(
    ps_gen: &PedersenGens,
    bp_gen: &BulletproofGens,
    proof: RangeProof,
    commitments: CompressedRistretto,
    n: usize,
) -> bool {
    let mut verifier_transcript = Transcript::new(b"rangeproof");
    proof
        .verify_single(&bp_gen, &ps_gen, &mut verifier_transcript, &commitments, n)
        .is_ok()
}

// Verifies multiple range proofs
/*fn range_verify_multiple(
    ps_gen: Vec<PedersenGens>,
    bp_gen: Vec<BulletproofGens>,
    proofs: Vec<RangeProof>,
    commitments: Vec<CompressedRistretto>,
    n: usize,
    number_of_proofs: usize,
) -> bool {
    for i in 0..number_of_proofs {
        // verify individual proofs
        let result = range_verify(&ps_gen[i], &bp_gen[i], proofs[i].clone(), commitments[i], n);

        // shortcut if any of the proofs is false, stop immediately
        if result == false {
            // only for benchmarking
            panic!("Verifying {}'th range proof failed!", i);
            //return false;
        }
    }
    return true;
}*/

/// Generates a linear proof
fn linear_proof(
    ps_gen: &PedersenGens,
    bp_gen: &BulletproofGens,
    private_value: Vec<Scalar>,
    public_value: Vec<Scalar>,
    n: usize,
) -> (
    LinearProof,
    (
        Vec<RistrettoPoint>,
        RistrettoPoint,
        RistrettoPoint,
        CompressedRistretto,
    ),
) {
    let mut rng = rand::thread_rng();
    let r = Scalar::random(&mut rng);

    let g: Vec<RistrettoPoint> = bp_gen.share(0).G(n).cloned().collect();
    let f = ps_gen.B;
    let b = ps_gen.B_blinding;

    // C = <a, G> + r * B + <a, b> * F
    let result_inner_product = inner_product(&private_value, &public_value);
    let c = RistrettoPoint::vartime_multiscalar_mul(
        private_value
            .iter()
            .chain(iter::once(&r))
            .chain(iter::once(&result_inner_product)),
        g.iter().chain(Some(&b)).chain(iter::once(&f)),
    )
    .compress();

    let mut prover_transcript = Transcript::new(b"linear proof");
    let proof = LinearProof::create(
        &mut prover_transcript,
        &mut rng,
        &c,
        r,
        private_value,
        public_value,
        g.clone(),
        &f,
        &b,
    )
    .expect("Error creating linear proof");

    (proof, (g, f, b, c))
}

/// Verifies a linear proof
fn linear_verify(
    proof: LinearProof,
    public_value: Vec<Scalar>,
    g: Vec<RistrettoPoint>,
    f: RistrettoPoint,
    b: RistrettoPoint,
    c: CompressedRistretto,
) -> bool {
    let mut verifier_transcript = Transcript::new(b"linear proof");
    proof
        .verify(&mut verifier_transcript, &c, &g, &f, &b, public_value)
        .is_ok()
}

// Verifies multiple linear proofs
/*fn linear_verify_multiple(
    proofs: Vec<LinearProof>,
    public_values: Vec<Vec<Scalar>>,
    commitments: Vec<(
        Vec<RistrettoPoint>,
        RistrettoPoint,
        RistrettoPoint,
        CompressedRistretto,
    )>,
    number_of_proofs: usize,
) -> bool {
    for i in 0..number_of_proofs {
        // verify individual proofs
        let result = linear_verify(
            proofs[i].clone(),
            public_values[i].clone(),
            commitments[i].0.clone(),
            commitments[i].1,
            commitments[i].2,
            commitments[i].3,
        );

        // shortcut if any of the proofs is false, stop immediately
        if result == false {
            // only for benchmarking
            panic!("Verifying {}'th linear proof failed!", i);
            //return false;
        }
    }
    return true;
}*/
