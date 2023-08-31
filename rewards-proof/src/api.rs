use bulletproofs::{PedersenGens, BulletproofGens, RangeProof, LinearProof, inner_product};
use curve25519_dalek::{ristretto::{CompressedRistretto, RistrettoPoint}, traits::VartimeMultiscalarMul};
use merlin::Transcript;
use curve25519_dalek::scalar::Scalar;
use core::iter;

/// Setup for Pedersen Generators and BulletProofs Generators
pub fn setup(gen_capacity: usize) -> (PedersenGens, BulletproofGens) {
    let pedersen_generators = PedersenGens::default();
    let bulletproof_generators = BulletproofGens::new(gen_capacity, 1);
    (pedersen_generators, bulletproof_generators)
}

/// Generates a proof and the commitments for a range proof
pub fn range_proof(ps_gen: &PedersenGens, bp_gen: &BulletproofGens, value: u64, n: usize) -> (RangeProof, CompressedRistretto) {
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
    ).expect("Error when creating rangeproof");

    (proof, commitments)
}

/// Verifies a range proof
pub fn range_verify(ps_gen: &PedersenGens, bp_gen: &BulletproofGens, proof: RangeProof, commitments: CompressedRistretto, n: usize) -> bool {
    let mut verifier_transcript = Transcript::new(b"rangeproof");
    proof.verify_single(
        &bp_gen,
        &ps_gen, 
        &mut verifier_transcript, 
        &commitments,
        n,
    ).is_ok()
}

/// Verifies multiple range proofs
pub fn range_verify_multiple(ps_gen: Vec<PedersenGens>, bp_gen: Vec<BulletproofGens>, proofs: Vec<RangeProof>, commitments: Vec<CompressedRistretto>, n: usize, number_of_proofs: usize) -> bool {
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
}

/// Generates a linear proof
pub fn linear_proof(ps_gen: &PedersenGens, bp_gen: &BulletproofGens, private_value: Vec<Scalar>, public_value: Vec<Scalar>, n: usize) -> (LinearProof, (Vec<RistrettoPoint>, RistrettoPoint, RistrettoPoint, CompressedRistretto)) {
    let mut rng = rand::thread_rng();
    let r = Scalar::random(&mut rng);

    let g: Vec<RistrettoPoint> = bp_gen.share(0).G(n).cloned().collect();
    let f = ps_gen.B;
    let b = ps_gen.B_blinding;

    // C = <a, G> + r * B + <a, b> * F
    let result_inner_product = inner_product(&private_value, &public_value);
    let c = RistrettoPoint::vartime_multiscalar_mul(
        private_value.iter().chain(iter::once(&r)).chain(iter::once(&result_inner_product)),
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
    ).expect("Error creating linear proof");

    (proof, (g, f, b, c))
}

/// Verifies a linear proof
pub fn linear_verify(proof: LinearProof, public_value: Vec<Scalar>, g: Vec<RistrettoPoint>, f: RistrettoPoint, b: RistrettoPoint, c: CompressedRistretto) -> bool {
    let mut verifier_transcript = Transcript::new(b"linear proof");
    proof.verify(
        &mut verifier_transcript, 
        &c, 
        &g, 
        &f, 
        &b, 
        public_value).is_ok()
}

/// Verifies multiple linear proofs
pub fn linear_verify_multiple(proofs: Vec<LinearProof>, public_values: Vec<Vec<Scalar>>, commitments: Vec<(Vec<RistrettoPoint>, RistrettoPoint, RistrettoPoint, CompressedRistretto)>, number_of_proofs: usize) -> bool {
    for i in 0..number_of_proofs {
        // verify individual proofs
        let result = linear_verify(proofs[i].clone(), 
                         public_values[i].clone(), 
                                    commitments[i].0.clone(), 
                                    commitments[i].1, 
                                    commitments[i].2, 
                                    commitments[i].3);

        // shortcut if any of the proofs is false, stop immediately
        if result == false {
            // only for benchmarking
            panic!("Verifying {}'th linear proof failed!", i);
            //return false;
        } 
    }
    return true;
}
