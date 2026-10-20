# How the labs work

Each lab is a small focused check written with the Node built in test runner, so there is no heavy framework to install. A lab connects to the node over the gateway, pulls a small piece of data, and asserts a property of it. When the node does not serve the data a check needs, the check fails with a reason that names what is missing. A check skips only when `QUANTOVA_OFFLINE` is set to 1.

## The verification approach

Lab 00 connectivity checks the node is reachable and reports a node identity and chain params, and that the head height grows between two reads taken a short time apart, using node_info, head, and chain_params.

Lab 01 signature scheme verifies real `ML-DSA-65` signatures and classifies a chain signature by byte length. Post quantum signatures are hundreds to thousands of bytes and classical signatures are about 64 bytes. Offline it signs a key registration for `Q-test-net-01` with a fresh key and checks that it verifies only under that chain id and genesis hash, and that a recorded registration from the retired `Q-test-net-1` is refused for `Q-test-net-01`. Live it finds a key registration in the last 200 blocks, or takes the one `QUANTOVA_KEY_REGISTER_TX` names, and verifies its signature over the pinned genesis hash and the signed body. The signed body must be a transfer of kind 0 to the key registration system address, the address of the SHA3 256 of `qtv/key/register`, and its arguments must be exactly the public key that hashes with its scheme byte to the sender address, a 1952 byte ML-DSA-65 key under scheme 1 or a 48 byte SLH-DSA key under scheme 2, whose 3309 or 16224 byte signature must verify, as the chain requires, so a gateway label alone never makes a transaction a registration. A chain signature must be exactly 3309 bytes under scheme 1 for ML-DSA-65 or exactly 16224 bytes under scheme 2 for SLH-DSA, the two schemes the chain accepts, and must close the recorded transaction bytes. The signed body must carry the chain id given by the first 8 bytes of the SHA3 256 of the network name.

Lab 02 no elliptic curve decodes an address as bech32m and checks it carries the Q prefix and a 32 byte payload rather than 20 byte hex. It also checks that the gateway does not expose methods named `ecrecover`, `ec_recover` or `recover_pubkey`.

Lab 03 committee and proposer checks the validators endpoint returns a well formed validator registry. It then reads the finality proofs of recent finalized blocks from get_finality and checks each against the validator roster the finality pin gives for the block's epoch. For each block it rebuilds the committee commitment from the pinned active validator set, the validators holding at least the minimum self stake of 2000 up to the 100 with the most stake, and checks that the certificate commits to it. Every committee reveal and every attestation must open the sortition root of its validator at the slot of the block. The proposer named in the certified header must be the validator the stake weighted rotation draws for that epoch and slot, or the one that follows it in rotation for each later view the block needed, and get_block must name the same proposer. When the gateway serves get_validator_set for that epoch, the served set must equal the pinned roster.

Lab 04 SHA3 hashing runs self verifying known answer tests and checks that a block hash is 32 bytes.

Lab 06 offline vectors needs no node and runs in CI. Its finality certificates were built for this repository and judged by the consensus code of the chain, and the lab requires the same verdict from the lab code. A valid certificate and one signed by exactly two thirds of the committee stake pass. A certificate with signatures dropped below two thirds, one with stake just below two thirds, one with an altered signature, one signed over another genesis, one whose envelope names a wrong committee digest and one with a trailing byte fail. It also holds certificates with attestations naming different views, with a validator below the stake floor left out and one where that validator signs, and with attesters proving membership at another slot, all judged by the consensus code. Three more certificates are refused by rules of the lab that go beyond the certificate check of the consensus code, a committee reveal that does not open its sortition root, a certified block with a cost other than the 1 every proposal carries, and a certificate naming another parent than its header. For a roster of 112 validators, more than the active set cap, the lab must derive the same active set, committee digest and rotation leader as the consensus code for 24 epoch and slot pairs. It runs Lab 05 against a recorded honest chain served on this machine, where all three of its tests must pass, against the same chain with a child whose beacon does not follow its parent, where the link test must fail, and with a finalized block certified over another genesis, where the lag test must fail because it checks every certificate it samples. It verifies an SLH-DSA key registration signed by the chain cryptography, refuses pin files that are links, pipes, directories or writable by others, and checks that a served validator set that differs from the pin is refused, that bech32m identifiers decode only in their canonical form with zero padding bits, and that malformed or out of range heights are refused.

Lab 05 finality reads the finalized height from finalized_head and verifies the certificate get_finality serves for it against the validator roster the finality pin gives for its epoch. Every attestation must be an `ML-DSA-65` signature under the attestation key of an active pinned validator, bound to the chain id and the pinned genesis hash, and the attesting validators must hold at least two thirds of the committee stake. The certified header must hash with SHA3 256 to the block identifier get_block reports. Two consecutive finalized blocks must link by parent hash and by the full committee beacon step. Over five samples the certificate of each sampled finalized height must verify against the pinned roster before the height is used, and the finalized height must never move back, never pass the head, and stay within 256 blocks of it. A gateway that does not serve finalized_head or get_finality fails the lab, and so does one whose get_validator_set differs from the pinned roster.

## The finality pin

Labs 03 and 05 never trust a validator set the node serves. They check every certificate against a genesis hash and validator roster you pin, so a gateway that fabricates a chain with its own validators fails them. The pin is a JSON file in the shape Q-Scaffold and QCore trustRoster use. It names `chain_id`, `genesis_hash` and `roster`, a list of validators each with `id`, `stake`, `bond_address`, `attest_pk`, `root` and `root_slots` exactly as get_validator_set serves them. Sortition roots change every epoch, so a pin may also carry `epochs`, a list of objects each naming an `epoch` and the `roster` for it. A roster listed for an epoch is used for that epoch, and the top level `roster` is used for any other. The labs read the pin from `QUANTOVA_FINALITY_FILE`, or from [../finality-pin.json](../finality-pin.json) in this repository. A pin file must be a regular file owned by the user who runs the labs that nobody else can write, and it is never read through a symbolic link, because whoever can write it decides which chain the labs accept. That file ships with an empty genesis hash and roster, and the `Q-test-net-01` values are filled in after the relaunch. With no pin set, the live labs that check certificates fail and say so. The labs are only as trustworthy as the source you took the pin from.

## Why signature size is the key signal

The most reliable external signal that a chain is post quantum is signature size. NIST post quantum signatures are large. ML-DSA-65 is about 3309 bytes and SLH-DSA runs from roughly 7.8 to 29 kilobytes, with the parameter set the chain uses at 16224 bytes, while classical elliptic curve signatures such as ECDSA and Ed25519 are about 64 bytes. A signature in the 64 byte band is a clear red flag, and one in a known post quantum band is strong evidence of a post quantum scheme. The reference bands are in [../lib/pq-schemes.js](../lib/pq-schemes.js).

## Response fields the labs read

Every live lab first calls node_info and requires `chain_id` and `genesis_hash` to match the pinned values. Heights must be whole numbers from 0 to 2^40, given as JSON numbers or as decimal strings without signs or leading zeros. Identifiers are bech32m strings written in capitals, at most 90 characters, with zero padding bits.

| Lab | Method | Fields read |
| --- | --- | --- |
| all live labs | `node_info` | `chain_id`, `genesis_hash` |
| 00 | `chain_params` | the whole object, printed |
| 00, 01, 02, 03, 04, 05 | `head` | `height` |
| 01 | `get_block` | `tx_ids`, to find a signed transaction and a key registration |
| 01 | `get_transaction` | `tx_id`, `kind`, `from`, `scheme`, `raw`, `signature` |
| 02 | `get_block` | `proposer` |
| 02, 03 | `validators` | `validators[].address`, `count` |
| 03 | `get_block` | `proposer` |
| 03, 05 | `finalized_head` | `head` |
| 03, 05 | `get_finality` | `height`, `epoch`, `chain_id`, `header_bytes`, `header_hash`, `certificate` |
| 03, 05 | `get_validator_set` | `epoch`, `chain_id`, `members[].id`, `stake`, `bond_address`, `attest_pk`, `root`, `root_slots`, compared with the pin only |
| 04 | `get_block` | `block`, `transaction_root`, `event_root` |
| 05 | `get_block` | `block` |

When a node names a field differently, the lab names the field it could not read and points here. Change the field name in the lab to match the node you test.

## Variables the labs read

| Variable | Default | Meaning |
| --- | --- | --- |
| `QUANTOVA_GATEWAY_URL` | `https://q-test-net-01.quantova.org` | The gateway to inspect. It must use https unless it is on this machine. |
| `QUANTOVA_CHAIN_ID` | `Q-test-net-01` | The chain name node_info must report. Its SHA3 256 also gives the chain id a signed body must carry. |
| `QUANTOVA_FINALITY_FILE` | `finality-pin.json` | The finality pin, a genesis hash and validator roster you trust. Labs 03 and 05 check certificates only against it. A file named here that is unreadable, for another chain, or empty fails the labs. |
| `QUANTOVA_GENESIS_HASH` | the pin's genesis hash | The genesis hash node_info must report, as 64 lowercase hex characters. When the pin also names one, the two must agree. The `Q-test-net-01` value is pinned after the relaunch, and until then the live labs fail unless a pin or this variable is set. |
| `QUANTOVA_OFFLINE` | `0` | Set to 1 to skip every check that needs a node. |
| `QUANTOVA_KEY_REGISTER_TX` | none | A key registration id for Lab 01 to fetch and verify. Without it Lab 01 looks for one in the last 200 blocks and fails if it finds none. |

The labs refuse to run when `NODE_TLS_REJECT_UNAUTHORIZED` is 0, so the gateway certificate is always checked. The same variables are listed in [../.env.example](../.env.example).
