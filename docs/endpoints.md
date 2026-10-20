# Endpoints

The gateway to point the labs at, and the methods they use.

## The gateway

The Quantova gateway is a plain HTTP surface. Every call is an HTTP POST to `/v1/<method>` with a flat JSON body. The response is JSON. Addresses are Q1 bech32m strings written with a capital Q. Heights and amounts are plain JSON numbers or decimal strings.

The `Q-test-net-01` gateway is at `https://q-test-net-01.quantova.org`. `Q-test-net-01` is a live network and only its native asset TQTOV is a test asset. Set the gateway in your environment.

```
export QUANTOVA_GATEWAY_URL=https://q-test-net-01.quantova.org
```

For the live consensus and finality labs, the most reliable target is a node you run, because a public endpoint may rate limit. Build instructions live in the consensus specification repository. An archive node gives full history.

## Gateway methods

The gateway exposes node_info, head, finalized_head, get_finality, get_validator_set, validators, chain_params, get_account, get_transaction, submit_transaction, get_block, supply, get_container, get_storage, and get_events, among others.

The labs read a subset of these. Every live lab starts with node_info to pin the chain. Connectivity uses head and chain_params. The signature lab uses head, get_block, and get_transaction. The no elliptic curve lab uses head, get_block, and validators. The committee and proposer lab uses validators, finalized_head, get_finality, and get_block, and reads get_validator_set only to compare it with the finality pin. The SHA3 lab uses head and get_block. The finality lab uses finalized_head, get_finality, head, and get_block, and reads get_validator_set only to compare it with the finality pin.

The no elliptic curve lab also probes for methods named ecrecover, ec_recover and recover_pubkey, which must not exist on a post quantum chain. Their absence is the expected result. It shows only that no method by those names is exposed.

Every response field the labs read is listed in the field table in [how-the-labs-work.md](how-the-labs-work.md). The full gateway reference lives in the developer documentation at https://quantova.org.
