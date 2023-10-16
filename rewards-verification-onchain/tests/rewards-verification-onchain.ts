import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { RewardsVerificationOnchain } from "../target/types/rewards_verification_onchain";
import * as assert from "assert";

describe("rewards-verification-onchain", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.RewardsVerificationOnchain as Program<RewardsVerificationOnchain>;

  // first testcase - verifying a reward proof sucessfully
  it("Rewards proof verification", async () => {
    // TODO construct parameters correctly
    const result:boolean = await program.rpc.verify_rewards_proof();
    if (result === true) {
      console.log("Proof verification successfull!");
    } else {
      console.log("Proof verification failed!");
    }
  });
});
