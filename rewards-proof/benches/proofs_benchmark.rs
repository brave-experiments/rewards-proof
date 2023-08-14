use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;
use rewards_proof::api::{setup, range_proof, range_verify, linear_proof, linear_verify};

fn criterion_benchmark(c: &mut Criterion) {
    benchmark_rangeproof(c);
    benchmark_linearproof(c);
}

fn benchmark_rangeproof(c: &mut Criterion) {
    let sum_of_counters: u64 = 254;
    let n: usize = 8;
    let (ps_gen, bp_gen) = setup(64);
    c.bench_function("rangeproof_prover", |b| b.iter(|| range_proof(&ps_gen, &bp_gen, sum_of_counters, n)));
    
    let (proof, commitments) = range_proof(&ps_gen, &bp_gen, sum_of_counters, n);
    c.bench_function("rangeproof_verifier", |b| b.iter(|| range_verify(&ps_gen, &bp_gen, proof.clone(), commitments, n)));
}

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

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
