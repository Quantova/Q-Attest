# Quantova Consensus Spec Test

Public verification labs for inspecting Quantova consensus. Point the labs at a Quantova node, either the public testnet or your own, and they check over the gateway that signatures are post quantum, that there is no elliptic curve recovery path, that leadership runs through the QORUS committee sortition, and that hashing is SHA-3.

Quantova is a post quantum Layer 1 blockchain, written to its own specification. The virtual machine is the QVM, a register machine that runs compiled containers. Consensus is QORUS, where a committee is sampled each round to attest to a proposed block and finality is recorded as a single aggregated certificate under ML-DSA-65, with the committee bounded by the budget the chain reports. Cryptography is Q-Crypto, a NIST post quantum suite written from scratch against the published FIPS documents, with ML-DSA-65 under FIPS 204 for signatures, ML-KEM-768 under FIPS 203 for key exchange, SLH-DSA under FIPS 205, SHA-3 and SHAKE under FIPS 202, and ChaCha20-Poly1305 for the transport channel.

This is a hands on companion to the consensus specification. The specification says how consensus works. These labs let anyone confirm that a running node behaves that way.

## What the labs check and what they do not

These labs are an inspection harness, not a security proof. Read [docs/what-the-labs-prove.md](docs/what-the-labs-prove.md) before drawing conclusions.

They confirm that a node exhibits the expected post quantum structure. That means post quantum signature schemes and sizes, no ecrecover and no secp256k1 path, Q1 bech32m addresses, QORUS committee sortition rather than a fixed or unbounded author set, SHA-3 hashing, and stable finality over the window observed.

They do not prove that the cryptography is unbreakable, that the implementation is free of side channels, or that no classical path exists elsewhere. Those questions rest on the NIST standardization of the underlying schemes and on independent review. The labs are evidence, not a substitute for that review.

## The gateway

The Quantova gateway is a plain HTTP surface. Every call is an HTTP POST to `/v1/<method>` with a flat JSON body. The methods are node_info, head, validators, chain_params, get_account, get_transaction, submit_transaction, get_block, supply, get_container, get_storage, and get_events. The full reference is in [docs/endpoints.md](docs/endpoints.md).

The testnet gateway is at `https://rpc-testnet.quantova.org`. Free TQTOV for the testnet is available from the faucet at https://quantova.org. TQTOV is the testnet asset. The mainnet asset is QTOV, and its base unit is the Quon, where one QTOV is one million Quon.

## Quickstart

```bash
git clone https://github.com/Quantova/Q-Attest.git
cd Q-Attest
npm install

# point the labs at a node
export QUANTOVA_GATEWAY_URL=https://rpc-testnet.quantova.org

# run every lab
npm test

# or run one lab
npm run lab:signature
```

The labs run against the official testnet gateway unless `QUANTOVA_GATEWAY_URL` names another one, and a gateway that cannot be reached or serves another chain fails the live labs rather than skipping them. Set `QUANTOVA_OFFLINE` to 1 to skip the labs that need a node, so `npm test` runs only the self verifying checks, for example the SHA3 256 known answer tests. The variables and their defaults are documented in [.env.example](.env.example).

## The labs

Lab 00 connectivity confirms the gateway is reachable, that it reports a node identity and chain params, and that the head advances.

Lab 01 signature scheme classifies a signature by byte length and confirms it is in the post quantum band. ML-DSA-65 is 3309 bytes, far above the roughly 64 byte classical band. It also verifies a real ML-DSA-65 signature rather than measuring one. It takes a key registration transaction and checks that its id is the SHA3 256 of the recorded bytes, that the registered public key hashes to the sender address, and that the signature verifies under that key over the signed body with the transaction context. A recorded registration is checked offline and the copy the chain serves is checked over the gateway. Set `QUANTOVA_KEY_REGISTER_TX` to check another registration. The check uses the native ML-DSA support in Node 24 or later and fails on an older Node rather than passing.

Lab 02 no elliptic curve confirms addresses are Q1 bech32m rather than 20 byte hex, and that the gateway exposes no ecrecover or secp256k1 recovery method.

Lab 03 committee sortition confirms the validators endpoint returns an active committee within the budget the chain reports, and that recent block authors are drawn from the validator registry.

Lab 04 SHA3 hashing runs self verifying known answer tests offline and confirms block hashes are 32 byte values on a live node.

Lab 05 finality stability confirms a finalized block is stable on re read and that finality lag stays bounded over a short window.

Shared helpers live in [lib](lib). The gateway client is in [lib/gateway-client.js](lib/gateway-client.js) and the post quantum size reference is in [lib/pq-schemes.js](lib/pq-schemes.js).

## Documentation

[docs/how-the-labs-work.md](docs/how-the-labs-work.md) describes the verification approach and how to adapt a lab to the node's exact responses. [docs/what-the-labs-prove.md](docs/what-the-labs-prove.md) states the honest scope, inspection against proof, and you should read it. [docs/endpoints.md](docs/endpoints.md) lists the gateway endpoints and the methods the labs use. [docs/address-key-binding.md](docs/address-key-binding.md) describes how an account is bound to its first public key.

## A note on adapting the labs

The labs are written against the documented Quantova gateway, but the exact field names and byte layout in a node's responses are confirmed against the running node. Where a lab depends on a specific response shape, for example where a block records its author, signature, or hash, that point is marked in the code with an ADAPT note. Confirm those against the node you test, then the live checks run.

## License

Copyright 2026 Quantova Inc. See [LICENSE.md](LICENSE.md). These labs are provided for inspection and educational use. They are not a security audit, a guarantee, or financial advice.
