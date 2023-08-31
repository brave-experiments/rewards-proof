use std::time::Duration;

use bulletproofs::{PedersenGens, BulletproofGens, RangeProof, LinearProof};
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use curve25519_dalek::{scalar::Scalar, ristretto::{CompressedRistretto, RistrettoPoint}};
use rewards_proof::api::{setup, range_proof, range_verify, linear_proof, linear_verify, range_verify_multiple, linear_verify_multiple};

fn criterion_benchmark(c: &mut Criterion) {
    //benchmark_rangeproof(c);
    //benchmark_linearproof(c);
    //benchmark_rewardsproof_generation(c);
    //benchmark_rewardsproof_verification(c);
    benchmark_rewardsproof_verification_multiple_users(c, 1000, 256);
    //benchmark_rewardsproof_verification_multiple_users(c, 100000, 64);
}

#[allow(dead_code)]
fn benchmark_rangeproof(c: &mut Criterion) {
    let sum_of_counters: u64 = 254;
    let n: usize = 8;
    let (ps_gen, bp_gen) = setup(64);
    c.bench_function("rangeproof_prover", |b| b.iter(|| range_proof(&ps_gen, &bp_gen, sum_of_counters, n)));
    
    let (proof, commitments) = range_proof(&ps_gen, &bp_gen, sum_of_counters, n);
    c.bench_function("rangeproof_verifier", |b| b.iter(|| range_verify(&ps_gen, &bp_gen, proof.clone(), commitments, n)));
}

#[allow(dead_code)]
fn benchmark_linearproof(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let n: usize = 64;
    let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let public_value: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

    let (ps_gen, bp_gen) = setup(n);
    c.bench_function("linearproof_prover", |b| b.iter(|| linear_proof(&ps_gen, &bp_gen, a.clone(), public_value.clone(), n)));
    
    let (proof, commitments) = linear_proof(&ps_gen, &bp_gen, a, public_value.clone(), n);
    c.bench_function("linearproof_verifier", |b| b.iter(|| linear_verify(proof.clone(), public_value.clone(), commitments.0.clone(), commitments.1, commitments.2, commitments.3)));
}

#[allow(dead_code)]
fn benchmark_rewardsproof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rewardsproof gen");

    let mut rng = rand::thread_rng();
    let value: u64 = 254;
    let limit_range_proof: usize = 8; // 2^8 is the limit
    // we need a maximum of 64-bit rangeproofs
    let (ps_gen, bp_gen) = setup(64);

    // set measurement time to 10 seconds
    group.measurement_time(Duration::new(10, 0));

    for size in [64 , 128, 256].iter() {
        //pre-processing
        let private_value: Vec<_> = (0..*size as usize).map(|_| Scalar::random(&mut rng)).collect();
        let public_value: Vec<Scalar> = (0..*size as usize).map(|_| Scalar::random(&mut rng)).collect();

        // create variables for linear proof
        let (ps_gen_lin, bp_gen_lin) = setup(*size as usize);

        // range proof stays the same, no matter the input size? depends if the limit changes with more ads?
        group.bench_with_input(BenchmarkId::new("rangeproof-", size), size, |b, _size| {
            b.iter(|| range_proof(&ps_gen, &bp_gen, value, limit_range_proof))
        });
        group.bench_with_input(BenchmarkId::new("linearproof-", size), size, |b, _size| {
            b.iter(|| linear_proof(&ps_gen_lin, &bp_gen_lin, private_value.clone(), public_value.clone(), *size as usize))
        });
    }
    group.finish();
}

#[allow(dead_code)]
fn benchmark_rewardsproof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("rewardsproof verify");

    let mut rng = rand::thread_rng();
    let value: u64 = 254;
    let limit_range_proof: usize = 8; // 2^8 is the limit
    // we need a maximum of 64-bit rangeproofs
    let (ps_gen, bp_gen) = setup(64);

    // set measurement time to 10 seconds
    group.measurement_time(Duration::new(10, 0));

    for size in [64 , 128, 256].iter() {
        //pre-processing
        let private_value: Vec<_> = (0..*size as usize).map(|_| Scalar::random(&mut rng)).collect();
        let public_value: Vec<Scalar> = (0..*size as usize).map(|_| Scalar::random(&mut rng)).collect();

        // create variables for linear proof
        let (ps_gen_lin, bp_gen_lin) = setup(*size as usize);

        // range proof stays the same, no matter the input size? depends if the limit changes with more ads?
        let (proof, commitments) = range_proof(&ps_gen, &bp_gen, value, limit_range_proof);
        group.bench_with_input(BenchmarkId::new("rangeproof-", size), size, |b, _size| {
            b.iter(|| range_verify(&ps_gen, &bp_gen, proof.clone(), commitments, limit_range_proof))
        });

        // linear proof
        let (linear_proof, linear_commitments) = linear_proof(&ps_gen_lin, &bp_gen_lin, private_value.clone(), public_value.clone(), *size as usize);
        group.bench_with_input(BenchmarkId::new("linearproof-", size), size, |b, _size| {
            b.iter(|| linear_verify(linear_proof.clone(), public_value.clone(), linear_commitments.0.clone(), linear_commitments.1, linear_commitments.2, linear_commitments.3))
        });
    }
    group.finish();
}

#[allow(dead_code)]
fn benchmark_rewardsproof_verification_multiple_users(c: &mut Criterion, number_of_users: usize, incentive_size: usize) { 
    // preprocessing
    let mut rng = rand::thread_rng();
    let value: u64 = 254;
    let limit_range_proof: usize = 8; // 2^8 is the limit

    let mut ps_generators: Vec<PedersenGens> = vec![];
    let mut bp_generators: Vec<BulletproofGens> = vec![];
    let mut ps_generators_lin: Vec<PedersenGens> = vec![];
    let mut bp_generators_lin: Vec<BulletproofGens> = vec![];
    let mut public_values: Vec<Vec<Scalar>> = vec![];

    let mut range_proofs: Vec<RangeProof> = vec![];
    let mut range_proof_commitments: Vec<CompressedRistretto> = vec![];

    let mut linear_proofs: Vec<LinearProof> = vec![];
    let mut linear_proof_commitments: Vec<(Vec<RistrettoPoint>, RistrettoPoint, RistrettoPoint, CompressedRistretto)> = vec![];

    // generate number_of_users proofs
    for _x in 0..number_of_users {
        // we need a maximum of 64-bit rangeproofs
        let (ps_gen, bp_gen) = setup(64);
        ps_generators.push(ps_gen);
        bp_generators.push(bp_gen.clone());

        //pre-processing
        let private_value: Vec<_> = (0..incentive_size).map(|_| Scalar::random(&mut rng)).collect();
        let public_value: Vec<Scalar> = (0..incentive_size).map(|_| Scalar::random(&mut rng)).collect();
        public_values.push(public_value.clone());

        // create variables for linear proof
        let (ps_gen_lin, bp_gen_lin) = setup(incentive_size);
        ps_generators_lin.push(ps_gen_lin);
        bp_generators_lin.push(bp_gen_lin.clone());

        // create multiple range proofs
        let (proof, commitments) = range_proof(&ps_gen, &bp_gen, value, limit_range_proof);
        range_proofs.push(proof);
        range_proof_commitments.push(commitments);

        // create multiple linear proofs
        let (linear_proof, linear_commitments) = linear_proof(&ps_gen_lin, &bp_gen_lin, private_value.clone(), public_value.clone(), incentive_size);
       linear_proofs.push(linear_proof);
       linear_proof_commitments.push(linear_commitments);
    }

    let mut group = c.benchmark_group("multiple rewards proofs verification");
    group.sample_size(10);
    group.measurement_time(Duration::new(7, 0));
    //group.sampling_mode(criterion::SamplingMode::Flat);
    // Verify proofs
    group.bench_function("multiple_range_proofs", 
                     |b| 
                     b.iter(|| range_verify_multiple(ps_generators.clone(), 
                                                              bp_generators.clone(), 
                                                              range_proofs.clone(), 
                                                              range_proof_commitments.clone(), 
                                                              limit_range_proof, 
                                                              number_of_users)
                    )
    );

    group.measurement_time(Duration::new(11, 0));
    group.bench_function("multiple_linear_proofs", 
                     |b| 
                     b.iter(|| linear_verify_multiple(linear_proofs.clone(), 
                                                               public_values.clone(), 
                                                               linear_proof_commitments.clone(), 
                                                               number_of_users)
                    )
    );
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
