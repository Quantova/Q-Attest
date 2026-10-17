# Endpoints

The gateway to point the labs at, and the methods they use.

## The gateway

The Quantova gateway is a plain HTTP surface. Every call is an HTTP POST to `/v1/<method>` with a flat JSON body. The response is JSON. Addresses are Q1 bech32m strings written with a capital Q. Heights and amounts are plain JSON numbers or decimal strings.

The testnet gateway is at `https://rpc-testnet.quantova.org`. Set it in your environment.

```
export QUANTOVA_GATEWAY_URL=https://rpc-testnet.quantova.org
```

For the live consensus and finality labs, the most reliable target is a node you run, because a public endpoint may rate limit. Build instructions live in the consensus specification repository. An archive node gives full history.

## Gateway methods

The gateway exposes node_info, head, validators, chain_params, get_account, get_transaction, submit_transaction, get_block, supply, get_container, get_storage, and get_events.

The labs read a subset of these. Connectivity uses node_info, head, and chain_params. The signature lab uses get_block. The no elliptic curve lab uses get_block and validators. The committee sortition lab uses validators, chain_params, and get_block. The SHA3 lab uses head and get_block. The finality lab uses head and get_block.

The no elliptic curve lab also probes for methods that must not exist on a post quantum chain, such as ecrecover. Their absence is the expected result.

Exact field names, and any committee or finalized height fields, depend on the node's serialization. See [how-the-labs-work.md](how-the-labs-work.md) and the ADAPT notes in the lab files. The full gateway reference lives in the developer documentation at https://quantova.org.
