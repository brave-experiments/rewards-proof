use anchor_lang::prelude::*;
use bulletproofs::{BulletproofGens, PedersenGens}; // do we need them or can we refactor it away?
use curve25519_dalek::scalar::Scalar; // curve25519 should be available as a system program?
use rewards_proof::api::{rewards_proof_verification, rewards_proof_setup};

declare_id!("3Vh4aL5iSVrXvsaKBHTLLAG5PEQycrDXFFs4VQP5zMuc");

#[program]
pub mod rewards_verification_onchain {
    use super::*;

    pub fn verify_rewards_proof(ctx: Context<VerifyRewardsProof>, data: Data) -> Result<()> {
        let state: &mut Account<ProofVerificationState> = &mut ctx.accounts.proof_state;
        let author: &Signer = &ctx.accounts.author;
        let clock: Clock = Clock::get().unwrap();

        state.author = *author.key;
        state.timestamp = clock.unix_timestamp;

        // TODO get policy vector from Brave backend
        let incentive_catalog_size: u64 = 64;
        let policy_vector: Vec<u64> = (0..incentive_catalog_size)
            .map(|_| 7) // for now just make it a fixed value
            .collect();
        let policy_vector_scalar: Vec<Scalar> = policy_vector
            .clone()
            .into_iter()
            .map(|u64_value| Scalar::from(u64_value))
            .collect();

        // generate generators here to get program compiling - FIX ME
        let (pedersen_gens, bulletproof_gens) = rewards_proof_setup(incentive_catalog_size);

        // verify proofs
        state.verified = rewards_proof_verification(
            //data.pedersen_generators,
            //data.bulletproof_generators,
            pedersen_gens, 
            bulletproof_gens, 
            data.range_proof,
            data.range_commitments,
            data.linear_proof,
            policy_vector_scalar,
            data.linear_commitments,
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct VerifyRewardsProof<'info> {
    #[account(init, payer = author, space = 1000)]
    pub proof_state: Account<'info, ProofVerificationState>,
    #[account(mut)]
    pub author: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct ProofVerificationState {
    pub author: Pubkey,
    pub timestamp: i64,
    pub verified: bool,
}

#[derive(AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone, Debug)]
pub struct Data {
    //pub pedersen_generators: Vec<PedersenGens>,
    //pub bulletproof_generators: Vec<BulletproofGens>,
    pub range_proof: Vec<u8>,
    pub linear_proof: Vec<u8>,
    pub range_commitments: Vec<u8>,
    pub linear_commitments: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    number_of_proofs: usize,
}
