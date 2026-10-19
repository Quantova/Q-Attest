# Quantova Consensus Spec Test

Public verification labs for inspecting Quantova consensus. Point the labs at a Quantova node, either one on the live `Q-test-net-01` network or your own, and they check over the gateway that signatures are post quantum, that the gateway exposes no elliptic curve recovery method by the names they probe, that the committee and proposer of each recent finalized block follow the QORUS draw, that hashing is SHA-3, and that finalized blocks carry certificates signed by two thirds of the committee stake.

Quantova is a post quantum Layer 1 blockchain, written to its own specification. The virtual machine is the QVM, a register machine that runs compiled containers. Consensus is QORUS, where a committee is sampled each round to attest to a proposed block and finality is recorded as a single aggregated certificate under ML-DSA-65. Cryptography is Q-Crypto, a NIST post quantum suite written from scratch against the published FIPS documents, with ML-DSA-65 under FIPS 204 for signatures, ML-KEM-768 under FIPS 203 for key exchange, SLH-DSA under FIPS 205, SHA-3 and SHAKE under FIPS 202, and ChaCha20-Poly1305 for the transport channel.

This is a hands on companion to the consensus specification. The specification says how consensus works. These labs let anyone confirm that a running node behaves that way.

## What the labs check and what they do not

These labs are an inspection harness, not a security proof. Read [docs/what-the-labs-prove.md](docs/what-the-labs-prove.md) before drawing conclusions.

They confirm that a node exhibits the expected post quantum structure. That means post quantum signature schemes and sizes, a gateway with no methods named `ecrecover`, `ec_recover` or `recover_pubkey`, Q1 bech32m addresses with a 32 byte payload, a committee that is the active validator set with every reveal opening its sortition root, proposers drawn by the stake weighted rotation, SHA-3 hashing, and finality certificates whose ML-DSA-65 attestations are bound to the pinned chain and come from two thirds of the committee stake.

They do not prove that the cryptography is unbreakable, that the implementation is free of side channels, that no classical path exists elsewhere, that the rotation is unbiased, or that finality is safe under adversarial conditions. Certificates are checked against the genesis hash and validator roster in the finality pin, never against a validator set the node serves, so a gateway that fabricates a chain with its own validators fails the labs. The labs are only as trustworthy as the source you took the pin from. Those questions rest on the NIST standardization of the underlying schemes and on independent review. The labs are evidence, not a substitute for that review.

## The gateway

The Quantova gateway is a plain HTTP surface. Every call is an HTTP POST to `/v1/<method>` with a flat JSON body. The methods include node_info, head, finalized_head, get_finality, get_validator_set, validators, chain_params, get_account, get_transaction, submit_transaction, get_block, supply, get_container, get_storage, and get_events. The full reference is in [docs/endpoints.md](docs/endpoints.md).

The `Q-test-net-01` gateway is at `https://rpc-testnet.quantova.org`. `Q-test-net-01` is a live network and only its native asset TQTOV is a test asset. Free TQTOV is available from the faucet at https://quantova.org. The mainnet asset is QTOV, and its base unit is the Quon, where one QTOV is one million Quon.

## Quickstart

```bash
git clone https://github.com/Quantova/Q-Attest.git
cd Q-Attest
npm install

# point the labs at a node and pin the genesis hash and validator roster you trust
export QUANTOVA_GATEWAY_URL=https://rpc-testnet.quantova.org
export QUANTOVA_FINALITY_FILE=/path/to/finality-pin.json

# run every lab
npm test

# or run one lab
npm run lab:signature
```

The labs run against the official `Q-test-net-01` gateway unless `QUANTOVA_GATEWAY_URL` names another one, and a gateway that cannot be reached or serves another chain fails the live labs rather than skipping them. The `Q-test-net-01` genesis hash and validator roster are pinned in [finality-pin.json](finality-pin.json) after the relaunch. Until then the live labs fail with that reason unless `QUANTOVA_FINALITY_FILE` names a pin you trust, and labs 00, 01, 02 and 04 also run when `QUANTOVA_GENESIS_HASH` names the genesis hash alone. Set `QUANTOVA_OFFLINE` to 1 to skip the labs that need a node, so `npm test` runs only the self verifying checks, for example the SHA3 256 known answer tests. Every variable the labs read is listed in [.env.example](.env.example) and explained in [docs/how-the-labs-work.md](docs/how-the-labs-work.md). A lab that cannot check a property because the node does not serve the data fails with a reason that says so.

## The labs

Lab 00 connectivity confirms the gateway is reachable, that it reports a node identity and chain params, and that the head height grows between two reads taken a short time apart.

Lab 01 signature scheme classifies a signature by byte length and confirms it is in the post quantum band and has exactly the size the chain accepts for its scheme, 3309 bytes for ML-DSA-65 under scheme 1 and 16224 bytes for SLH-DSA under scheme 2, far above the roughly 64 byte classical band. It also verifies real ML-DSA-65 signatures rather than measuring them. Offline it signs a key registration for `Q-test-net-01` with a fresh key and checks that it verifies only under that chain id and genesis hash, and that a recorded registration from the retired `Q-test-net-1` is refused. Live it finds a key registration in the last 200 blocks, or takes the one `QUANTOVA_KEY_REGISTER_TX` names, and checks that its id is the SHA3 256 of the recorded bytes, that the signed body is a transfer of kind 0 to the key registration system address whose arguments are exactly the registered ML-DSA-65 or SLH-DSA public key, that this key hashes to the sender address, and that the signature verifies under that key over the pinned genesis hash and the signed body, whose chain id must be the first 8 bytes of the SHA3 256 of the network name. The check uses the native ML-DSA support in Node 24 or later and fails on an older Node rather than passing.

Lab 02 no elliptic curve decodes an address as bech32m and confirms it carries the Q prefix and a 32 byte payload rather than 20 byte hex, and that the gateway does not expose methods named `ecrecover`, `ec_recover` or `recover_pubkey`.

Lab 03 committee and proposer confirms the validators endpoint returns a well formed validator registry. For recent finalized blocks it reads the certificate from `get_finality` and checks it against the validator roster pinned for the block's epoch, rebuilds the committee commitment from the pinned active validator set and checks the certificate commits to it, checks every committee reveal and attestation opens the sortition root of its validator at that slot, and checks the proposer is the validator the stake weighted rotation draws for the slot. When the gateway serves `get_validator_set` for that epoch, it must equal the pinned roster.

Lab 04 SHA3 hashing runs self verifying known answer tests offline and confirms block hashes are 32 byte values on a live node.

Lab 05 finality reads the finalized height from `finalized_head` and verifies its certificate from `get_finality` against the pinned roster. Every attestation must be an ML-DSA-65 signature under the key of an active pinned validator, bound to the chain id and the pinned genesis hash, and the attesters must hold at least two thirds of the committee stake. The certified header must hash to the block identifier `get_block` reports, two consecutive finalized blocks must link by parent hash and beacon, and over five samples the certificate of each sampled finalized height must verify against the pinned roster before the height is used, and the finalized height must never move back, never pass the head, and stay within 256 blocks of it. A gateway that does not serve `finalized_head` or `get_finality`, or that serves a `get_validator_set` other than the pinned roster, fails the lab.

Lab 06 offline vectors runs without a node, in CI as well. It checks finality certificates generated and judged by the chain's own consensus code, so a valid certificate and one signed by exactly two thirds pass, while a dropped or altered signature, stake below two thirds, a wrong committee digest, another genesis and a trailing byte fail. It also checks mixed views, the stake floor, attester membership, the active set cap, the committee digest and the rotation leader against the consensus code, three stricter rules of the lab, Lab 05 itself against a recorded chain served on this machine, an SLH-DSA key registration signed by the chain cryptography, pin file modes, a served validator set that differs from the pin, bech32m padding and length, and malformed heights.

Shared helpers live in [lib](lib). The gateway client is in [lib/gateway-client.js](lib/gateway-client.js) and the post quantum size reference is in [lib/pq-schemes.js](lib/pq-schemes.js).

## Documentation

[docs/how-the-labs-work.md](docs/how-the-labs-work.md) describes the verification approach and lists every response field and variable the labs read. [docs/what-the-labs-prove.md](docs/what-the-labs-prove.md) states the honest scope, inspection against proof, and you should read it. [docs/endpoints.md](docs/endpoints.md) lists the gateway endpoints and the methods the labs use. [docs/address-key-binding.md](docs/address-key-binding.md) describes how an account is bound to its first public key.

## A note on response fields

The labs are written against the Quantova gateway. Every response field a lab reads is listed in the field table in [docs/how-the-labs-work.md](docs/how-the-labs-work.md). When a node you test names a field differently, the lab reports which field it could not read and points to that table.

## License

Copyright 2026 Quantova Inc. See [LICENSE.md](LICENSE.md). These labs are provided for inspection and educational use. They are not a security audit, a guarantee, or financial advice.
