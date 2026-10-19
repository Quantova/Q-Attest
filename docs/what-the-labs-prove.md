# What the labs prove and what they do not

Read this before citing these labs as evidence of anything. Being precise here is the difference between a credible verification tool and an over claim.

## What the labs do establish

When run against a node, the labs provide evidence that the node exhibits a post quantum structure.

Signatures in the inspected path are post quantum by size, not classical 64 byte signatures, a key registration is a transfer to the key registration system address carrying exactly the ML-DSA-65 or SLH-DSA key it registers, and its signature verifies under that key for the chain id of the network named and the pinned genesis hash. The inspected address decodes as Q1 bech32m with a 32 byte payload, and the gateway does not expose methods named ecrecover, ec_recover or recover_pubkey. Recent finalized blocks were proposed by the validator the stake weighted rotation draws for their slot. Their certificates commit to the active validator set of the pinned roster, every committee reveal and attestation opens the sortition root of its validator, and the attestations are ML-DSA-65 signatures bound to the pinned chain id and genesis hash from validators holding at least two thirds of the committee stake. Hashing is SHA-3 with 32 byte digests, the certified header hashes to the block identifier the node reports, and the lab's own SHA3 256 is correct by known answer test. Consecutive finalized blocks link by parent hash and beacon, and the finalized height never moves back over the samples taken, never passes the head and stays within 256 blocks of it.

This is meaningful. It is direct reproducible evidence that the running system behaves the way the consensus specification says.

## What the labs do not establish

These labs are an inspection harness, not a proof of security. They do not show that the cryptography is unbreakable. The strength of ML-DSA and SLH-DSA rests on their NIST standardization and on the underlying hard problems, not on a connectivity test. They do not show that the implementation is correct. Correct parameter sets, constant time behavior, absence of side channels, and correct serialization are matters for independent review, not for these labs. They do not show that no classical path exists anywhere, because the labs inspect specific paths and cannot prove a negative across the whole system. They check the committee, the proposers and the certificates against the genesis hash and validator roster you pin, never against a set the node serves, so a gateway that fabricates a chain with its own validators fails them. They do not show that the pinned roster is the right one, which rests on where you took the pin from. They do not show that the rotation is unbiased or that finality is safe under adversarial conditions. Labs 03 and 05 inspect a sample of recent blocks on one node. Neither is a formal analysis. When a node does not serve the data a check needs, that check fails and says why.

## The honest summary

These labs let anyone independently confirm that a Quantova node presents the expected post quantum behavior.

The labs complement the NIST standardization of the schemes and do not replace it. Treating the labs as evidence is correct. Treating them as a security proof is not.
