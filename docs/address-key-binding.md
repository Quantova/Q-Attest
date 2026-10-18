# Address key binding

This note describes how a Quantova account is bound to its public key. It is a design note.

## Addresses

A Quantova address is a Q1 bech32m string written with a capital Q. It is derived from an ML-DSA-65 public key with SHA-3. The address commits to the key, so the account and the key that controls it are tied together at the hashing step.

## The second preimage consideration

A hash based address commits to a key through a digest. Under a quantum attacker, Grover search reduces the effective second preimage margin of a digest of width n to about n over two. An account is safest when the running rules accept only the exact key the account is known to control, rather than any key that happens to hash to the same address.

## Key binding

The approach is to bind an account to the first public key it signs with. On first use the account records the key it presents. On every later transaction the presented key must match the recorded key. A different key, even one that a search produced to land on the same address, is rejected. The chain stores the digest of the key rather than the full key, so the state cost per active account is small.

The residual is that a funded address that has never signed is bound only on its first use, the same model as any chain that reveals a key on first spend. Binding protects every account from its first legitimate transaction onward. It is best enabled early, before broad adoption.

## Honesty

This note describes a design approach. Report issues through the security documentation repository.
