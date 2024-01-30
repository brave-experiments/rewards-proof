# Boomerang Protocol - Rewards Proof

This repository contains the proof-of-concept code for the rewards proof of 
'The BOOMERANG protocol: A Decentralised Privacy-Preserving Verifiable
Incentive Protocol'. The technical details can be found in our 
[research paper](https://arxiv.org/pdf/2401.01353.pdf). 

*Warning*: This code is a research prototype. Do not use it in production.

## The BOOMERANG protocol

We propose the BOOMERANG protocol, a novel decentralised privacy-preserving 
incentive protocol that leverages cryptographic black box accumulators to 
securely store user interactions within the incentive system. Moreover, the 
protocol employs zero-knowledge proofs based on BulletProofs to transparently 
compute rewards for users, ensuring verifiability while preserving their 
privacy. To further enhance public verifiability and transparency, we utilise a 
smart contract on a Layer 1 blockchain to verify these zero-knowledge proofs. 
The careful combination of black box accumulators with selected elliptic curves 
in the zero-knowledge proofs makes the BOOMERANG protocol highly efficient.
Our proof of concept implementation shows that we can handle up to 23.6 million 
users per day, on a single-threaded backend server with financial costs of 
approximately 2 US$. Using the Solana blockchain we can handle 15.5 million 
users per day with approximate costs of 0.00011 US$ per user. The versatility 
of the the BOOMERANG protocol is demonstrated through its applications in 
personalised privacy-preserving advertising, data collection, and health and 
fitness tracking. Overall, the BOOMERANG protocol represents a significant
advancement in privacy-preserving incentive protocols, laying the groundwork for
 a more secure and privacy-centric future.

## Build & Run

### Requirements

In order to build and run the library for the rewards proofs, you will need the 
following:

    Rust >= 1.72.0-nightly (nightly-2023-06-03)
    Cargo

Moreover, we depend on our 
[own (modified) fork](https://github.com/brave-experiments/bulletproofs/tree/boomerang) 
of the BulletProofs library from 
[dalek-cryptography](https://github.com/dalek-cryptography/bulletproofs), which 
should be added as a git submodule. This can be done by running the following 
steps when cloning the repository:

    git clone git@github.com:brave-experiments/rewards-proof.git
    git submodule init
    git submodule update

### Building

To install the latest version of Rust, use the following command (or 
alternatively check the 
[Rust documentation](https://www.rust-lang.org/tools/install) on how to install 
Rust)

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

To build the library, run

    cargo build

### Running Benchmarks

To run benchmarks for the results presented in the research paper, run

    cargo bench --bench proofs_benchmark

which will run the benchmarks defined in 
`rewards-proof/benches/proofs_benchmark.rs` file. Note, the process is slow and 
takes on average 5 minutes on a normal laptop. To speed up the benchmarks, it is 
possible to edit the benchmark file and only run specific benchmarks. 

We also run our benchmarks on an `AWS EC2 t2.large` instance, where comparison 
numbers are available in the 
[research paper](https://arxiv.org/pdf/2401.01353.pdf) (Section 7). 

There are three functions that are benchmarked when running the command for the 
benchmarking above. 

    fn benchmark_rewardsproof_generation(c: &mut Criterion)
    fn benchmark_rewardsproof_verification(c: &mut Criterion)
    fn benchmark_rewardsproof_verification_multiple_users(c: &mut Criterion, number_of_users: usize, incentive_size: usize)

The first one `fn benchmark_rewardsproof_generation(...)` generates a reward 
proof for different sizes of the incentive vector (`64/128/256` entries) and 
then benchmarks the generation of the reward proof. The second 
`fn benchmark_rewardsproof_verification(...)` benchmarks the verification of the
 rewards proof (with same setup as previous function). 
The function `fn benchmark_rewardsproof_verification_multiple_users(...)` 
creates rewards proofs for `number_of_users: usize` with a fixed 
`incentive_size: usize` (must be either `64`, `128` or `256`), and then does a 
batch verification of all generates proofs, where the verification of the 
multiple proofs is benchmarked.

If the benchmarks finished without any errors you should see the individual 
benchmark results printed to the standard output. We use 
[Criterion](https://bheisler.github.io/criterion.rs/book/index.html) for 
benchmarking. Detailed benchmark results are stored in 
`target/criterion/report/index.html`, that you can open in your browser to 
inspect the results.

### Running Examples

The code contains one simple example of generating a rewards proof and verifying
 the rewards proof. To run the example, run

    cargo run --example example_proofs

For details see `rewards-proof/examples/example_proofs.rs` file. 

## Main Functionality

The rewards-proof library provides the zero-knowledge proofs for computing a 
rewards proof as outlined in Section 5.1 in the 
[research paper](https://arxiv.org/pdf/2401.01353.pdf). The source code for the 
rewards proofs is located in the `rewards-proof/src` directory. In particular: 
* `api.rs`: provides a simple API:
  * `rewards_proof_setup`: This function creates the Generators needed for the 
zero knowledge proofs. In more detail it generates the Pedersen generators and 
Bulletproof generators for both the range proof and the linear proof and returns 
them.
  * `rewards_proof_generation`: This function creates the non-interactive 
zero-knowledge proof, and returns two proofs (range proof and linear proof) as 
well as the commitments for both range/linear proof. This function should be run
 on the client by the user.
  * `rewards_proof_verification`: This function takes the above generated proofs
 and commitments and verifies their correctness. This function should be run on 
the backend server of the issuer. 
  * `rewards_proof_verification_multiple`: To support multiple proof 
verifications as batch verifications, this function takes a vector of the proofs
 that are generated from the clients, and verifies multiple proofs at once. This
 function should be run on the backend server of the issuer.

### How to use/integrate

The rewards proof is developed as a library so that it can easily be integrated 
into other projects. We provide a simple API with all the necessary functions to
generate proofs and verify them, as outlined above. 

In the following we give an example, which also can be found in 
`./rewards-proof/examples/example_proofs.rs` and can be run with the following 
command:
    cargo run --example example_proofs

The example first generates the incentive/reward of an user by calculating the 
inner product of the interacting with the incentives (state) and the policy 
vector (defining how to reward different incentives):

    reward = <state, policy_vector>

as defined in Section 5 of the 
[research paper](https://arxiv.org/pdf/2401.01353.pdf). Then it generates the 
rewards proof and commitments using `rewards_proof_generation(...)`. Finally, in
 the example, we directly verify the correctness of the proof by calling the 
`rewards_proof_verification(...)` function with the proof and commitments. 

In an actual implementation, the 
proof generation should be done by the client, and the proof verification should 
be done on a backend (or within a smart contract of a blockchain as outlined in 
the [research paper](https://arxiv.org/pdf/2401.01353.pdf) in
Section 6).

    use curve25519_dalek::scalar::Scalar;
    use rand::Rng;
    use rewards_proof::api::{
        rewards_proof_generation, rewards_proof_setup, rewards_proof_verification,
    };

    let mut rng = rand::thread_rng();
    let incentive_catalog_size: u64 = 64;
    let (pedersen_gens, bulletproof_gens) = rewards_proof_setup(incentive_catalog_size);

    // public value
    let policy_vector: Vec<u64> = (0..incentive_catalog_size)
        .map(|_| rng.gen_range(0, 10))
        .collect();
    let policy_vector_scalar: Vec<Scalar> = policy_vector
        .clone()
        .into_iter()
        .map(|u64_value| Scalar::from(u64_value))
        .collect();
    // private value
    let state: Vec<u64> = (0..incentive_catalog_size)
        .map(|_| rng.gen_range(0, 10))
        .collect();
    let state_scalar: Vec<Scalar> = state
        .clone()
        .into_iter()
        .map(|u64_value| Scalar::from(u64_value))
        .collect();

    // reward = <state, policy_vector>
    let reward: u64 = state
        .iter()
        .zip(policy_vector.iter())
        .map(|(x, y)| x.checked_mul(*y))
        .flatten()
        .sum();

    // generate rewards proof
    let (range_proof, linear_proof, range_comm, linear_comm) = rewards_proof_generation(
        pedersen_gens.clone(),
        bulletproof_gens.clone(),
        reward,
        state_scalar,
        policy_vector_scalar.clone(),
        incentive_catalog_size,
    );

    // verify rewards proof
    if rewards_proof_verification(
        &pedersen_gens,
        &bulletproof_gens,
        range_proof,
        range_comm,
        linear_proof,
        policy_vector_scalar,
        linear_comm,
    ) {
        println!("Rewards proof verification successfull!");
    } else {
        println!("Rewards proof verification failed!");
    }

## Citation

    @misc{ankele2024boomerang,
          title={The Boomerang protocol: A Decentralised Privacy-Preserving Verifiable Incentive Protocol}, 
          author={Ralph Ankele and Hamed Haddadi},
          year={2024},
          eprint={2401.01353},
          archivePrefix={arXiv},
          primaryClass={cs.CR}
    }
