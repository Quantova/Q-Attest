# What the labs prove and what they do not

Read this before citing these labs as evidence of anything. Being precise here is the difference between a credible verification tool and an over claim.

## What the labs do establish

When run against a node, the labs provide evidence that the node exhibits a post quantum structure.

Signatures in the inspected path are post quantum by size, not classical 64 byte signatures. The account layer is Q1 bech32m, and there is no ecrecover or secp256k1 recovery path. Leadership runs through the QORUS committee, drawn by sortition and bounded by the budget the chain reports, rather than a fixed or unbounded author set. Hashing is SHA-3 with 32 byte digests, and the lab's own SHA3 256 is correct by known answer test. Finalized blocks are stable on the node observed and finality lag is bounded.

This is meaningful. It is direct reproducible evidence that the running system behaves the way the consensus specification says.

## What the labs do not establish

These labs are an inspection harness, not a proof of security. They do not show that the cryptography is unbreakable. The strength of ML-DSA and SLH-DSA rests on their NIST standardization and on the underlying hard problems, not on a connectivity test. They do not show that the implementation is correct. Correct parameter sets, constant time behavior, absence of side channels, and correct serialization are matters for independent review, not for these labs. They do not show that no classical path exists anywhere, because the labs inspect specific paths and cannot prove a negative across the whole system. They do not show that the sortition draw is unbiased, and they do not show that finality is safe under adversarial conditions. Lab 03 reads the committee and Lab 05 observes stability over a sampling window on one node. Neither is a formal analysis.

## The honest summary

These labs let anyone independently confirm that a Quantova node presents the expected post quantum behavior.

The labs complement the NIST standardization of the schemes and do not replace it. Treating the labs as evidence is correct. Treating them as a security proof is not.
