// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { encodeBech32m } from "../lib/bech32m.js";
import { printable } from "../lib/printable.js";
import { EXPECTED_CHAIN_ID, HAS_ENDPOINT, LIVE_NETWORK, QuantovaGateway } from "../lib/gateway-client.js";
import {
  chainIdFor,
  classifySignature,
  nativeMlDsaAvailable,
  parseTransactionBody,
  transactionChainId,
  verifyKeyRegistration,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SIGNATURE_BYTES,
  PQ_MIN_BYTES,
  CLASSICAL_MAX_BYTES,
  CHAIN_SIGNATURE_BYTES,
  KEY_REGISTER_TARGET,
  SCHEME_ML_DSA_65,
  TRANSACTION_CONTEXT,
} from "../lib/pq-schemes.js";

const skip = !HAS_ENDPOINT;
const LIVE_NETWORK_CHAIN_ID = 6995079887857407393n;
const RETIRED_NETWORK = "Q-test-net-1";
const WINDOW = 200;
const MAX_LOOKUPS = 400;
const NAMED_KEY_REGISTRATION_ID = process.env.QUANTOVA_KEY_REGISTER_TX || null;

const RETIRED_Q_TEST_NET_1_REGISTRATION_RAW = [
    "2000000000000000e7afccf8fa3c1fb6ddd6acf81c9c8e407421e2282c8d3aa8ac904e8a6e2c0c1d0000000000000000",
    "ba04000000000000f4010000000000000000000000000000200000000000000008edfca9bb5d48c0d84549e4ca89bbc3",
    "568ed3eee0cb494c6cb7ff23cfe7f64fa007000000000000df77ccf6eb6b0858c0b8cbdc3663ac833eed690037ce296a",
    "cfd8f0e4ac9d6f3f7e8b927029b0bf9966784b83f4465d27ad3d39c71e4e619c17a03515c8655f1da414d237009ea337",
    "85902fa18e59edfcc807d4ea37724af5b7ad683f910262c4bdb47c787dedf689c8b03dbf83b75348bef9f7a1feeb8c8a",
    "3226fda236d6382777aa394048217c1b1c1b2c4e8c8edf70f13f012f755774655e8bc817ffaf6f81de88ba260f599018",
    "acd61f4d8894e946291b7b90384a1c9ae09666ebbb10a5a3472d62f7d20a5d95646bd3574cc0e1bb28c23b9411e33b6e",
    "79ed536ad2568e27ab78c08f79877292ef1f692ecf16095b2bca9b16cb11cb6b89346b06211783a10becab0f683a0862",
    "871ddaeb9662c75e25b29bc31d6d69750627b6660ba452d559b0eb495dc4f98a673af9498842f5271c2dfe140da5fc4a",
    "3de70a58c6099c73bc01005525fd13cc016cf1050ed410ea411701450ba5ce9833dd8a525c240cc68dd2ce5a20875670",
    "bd7671d6892225e217fb596dac7abe99185d241512bd4bb0a32b88c9b8db154d15f71c115061b24f099940d1c257f809",
    "882bfb4a57ff61da8a163ebe68f1e2d0d33c7c7f61068fced8879f73fabf825565a1adbc13e51b4b3805b63667ebe19a",
    "46b7365f614948ad9b8cf1e8699e3d72f12bbfdfa0b81b26f7357bbe6254400ebb479ee6ee5224ad8cd8ab62d6779a7f",
    "d9a012f6d759d44ca6c4f895e5056877963b71525267d50a5283ca72a24d65e168d38562df00a90752e9916e11408573",
    "c4fa6583d33a34789bd87dab44065aab4635151ee06d51dd97c0b46177af094069520f07f2ee83bf50d956fa55aba7c7",
    "88010023f9133217dd7ace2e190352377f03e92ca9d8b44064d3ea313e07d010d51890961a718561030603a435f07039",
    "34f0cffbf2fafdaf6e80cce4b2c3aaf0d6a6ed8db6b375c761565eb29c9aa6e5498f3c640afeed49d6cfdf4f0798fbc4",
    "116f92991b7cfd56de4a65be386cdd5081b5f5ecd90d0d165f02cfff44012368ecf669fa1ba592efeb8c3939a3da64ef",
    "42b336a6c30f6df95bb217b368cd0c0415e8c291288a0add61af04b6b818b9c5c8d2d688326da8ac663fadc66d06149e",
    "87385043208db7eb0fac12987419eae9afc5990e0a3b137b771e4af122b9e74125ae2043f3d7ad04692cbb0e0e1e4f29",
    "074f699c327f1f50f6fc7d9e137420aace468b563cd8cf782fcc10548b4e1831f8cfd094103bed0fcaad4882ecfb5b38",
    "9a51c3dacebf6389694ab0785f1be4bd943478b2739ab6cafa0d66d104a803926d55d118cfa64687a6bfd1bebc31dc6d",
    "5b1811ee1021c936a0c7b662b9b949edf7698fadf0df55e16c3e97d468121b85502b5e56cb051eea1fdffcc0eee74f4b",
    "e425af1e4af407df8e5448510c95b9ea766e60909bf209aa768e1c2599bbd0e24b96cf4e3a361f38b3ca430d87ff7ae8",
    "fb12018cd37113407659d02895e96b79578b11a147d47bbbd3777b8e3fcd44545543564af347b24edbeb08b21a734566",
    "253e9f784e5429f55a1e63cd1b8c272b2b521d0a286f276f4550bb33bf3c9a0bd06e9836ecb5042f668511637ec701c1",
    "32e7f508b59fa830e2c975cc11326a47265865115927c00f8f06aeb289440bfdec3700352a78d7bc2e01dca19c4044d5",
    "94fb41908821e67da8dd3a753d5ae0e4e299285b1931118616752c3f5170fbf8fdbb5d2e5bd722285c11a673ae60a3d6",
    "57dfb9e020c02b29a7c18b655ec1384c1ea4b5ce90b13cfcc5e71905569182f04f94e6c451e62cbd377149c1eea9f7d2",
    "f62e823e833fa431a3d6c2b853fea6d01760e2710e6bf15085a4a5edc2cbadd1a8175113964db88a8dbd55c0ed280cb6",
    "493a697f955d6e8c14fa695f2f374112f35d8abf1d582bf11bd638719b93160d72c8a98dd6866609ccd831a6abd85e96",
    "dc530fa0d048c0cedc9842772620d140b3ed3cdffbe451238984e9a3b330fcc84baa5e7eeaeac5897c4003434f71403b",
    "7b523b536d5ae4f2e7eb8314b664f10965e330b631d82d2ad1787e4a83602961e3ad1c27fa7bd37b1e34691f5ad15334",
    "bf58257048ad01b61d82d9bb33a36bce8fb5b615e258bbff09877bda5e92fcfbbe04b105318e61598b2a1d3d63c72c48",
    "69cb8c9711c512000cd08faf8da4034875bec960626576f4b6ad5da7f62508e309e7cef9f2d6fb1e6c3758df48e3b48e",
    "b700725fdf36b5c0ac73c2c20ae9cec7ab65614c1e7bc2e9761858503de31c63160a2f2911d8aedbef52e639af71106d",
    "9127510bfe4531a9c9ea099f36be421f49c9474628d1ce6cf942d94eb37d3a858644bfd971fd92eeca64ea3093b15018",
    "f2389641e2249cb52e2414da2a490e1d2c6597f568e92851c09c32ca40ef6a8c794a332982b1ad88ae1dc45697d84b97",
    "5029fb333958156a8fa8a35ba5197c2607c4b14924433a8a858f9a85d6a551db3a133a3b5c3e0f17ec8997000112356c",
    "fa2248938855208320f58e361a0e5679e15192107abaeb812ce027af82ceb531b5304a00e93116ce75d705d9244d2b42",
    "326e5f59d3cbdbb519f5910b4b58e3572d9b849590afb2a029aeeba1077412897667af3be4ffde109307f90825cd032c",
    "2f563df046fc3a0200c51965aaf7edb9424a133a31a82de283f4e33ff29cfadd6df689b28f3558d1dc7951be84c04542",
    "90b35dc91f4414e43db72ef74e9ef1650eee2b7a166fc0ac4b15cc2f5895f11f394ac1844125db5fbe99abe39530724b",
    "c1df3668981fa5a80000000000000000ae06898526dcf637000000000000000038050000000000000001ed0c00000000",
    "000017c42b4bbca7987b6aa81434c58c2e0abc0369b6c984417876cfca80546dacbdf0635d38dd55225edc7b032bbf4d",
    "f837d7c71cdf348eeb7f9e82dbff7ea15d2670e60a4cc0c585f8018a73dda92eb99162ab60dd8537f66c4cce9d812034",
    "26b9e16a73fd59833819751ef029bc8db51fc4c14cfbc33b29243140cbf70da9db534d99d415f2355dfeaa9828d599a6",
    "64680256cdda4d855bbd2f68850b61940eff7cdb90139312ecfb4be682b2b91ba4f5e235dec3dd72544e6eaf28540e69",
    "e5aa6429592cfc3a235620e9b0239a290621a79f35793bd8a687e313142594fc2118c8d6bbe92f605f06e5d2a0c50634",
    "25e24f536ebd7fddf699d1baf6274e0750cf6edd68ee15ad3eae500858a0e8a7903ffea81f603e7cffa632143bb65582",
    "f9b4a6f0edd85d835bfa81d3ce1eafc8cb9abc9eabd842baae83ff0846c72475fa41100e811b13ed910e700fcfa6e270",
    "ea377440dbc1579be0234e25532552bc86bebfd0d9f89876770e644cb8636b603f6bfe373b4018a1b106ba1384099313",
    "589842b381c9823bbc74e98ebb681369f84bf3dfdcda06fb39658c0c81ef4ffc078886355b417e610c1a5f132df393e3",
    "92caa58e2a3311d3cdb158e1f33d635cc2eac95983e266874316263d82fd87e32af4a830b87efcc9bd320d79e3d2546c",
    "46d1f577f0880ab5c418324086512b13560e07d88c5c1d281e3d99869dbc6578387efccc09d31a5bb289364eb7f1db54",
    "63580413d4499ae1acbd8f39dee5083d35de904f2bc1a43f656431caa79bb67059ccd3c4fcbcae9add27fd093f7253ec",
    "aa22c038e9a70c776f79ea2e0abed54282c0f1cddaecf8d5bf66da2c2182afafe786721b222fe44c68ed888b143893fb",
    "f3eb0eac2d7834b819c7f9c2b74268209b7da7df720f98187dc18c2aa4ab031703f439562bbb3585aef6e8112a29493e",
    "53ca2496cd250f3867ae064df9bd3db91eb647872c701065e3df7f356dd601460e909732d80bac3e8ec76daeac136d19",
    "01346af3d885a071c1b38fd82505210c52685efc94b239324f3e00ee9d63d3c972721db6f8a53cdfcdc4b5f85fdaffbe",
    "ba1193bb48cd65557b3622765fe9399d0eec2044682ffe7545266aa51a62e2a75b1ada2fdbb083f1d6d7c7be00ce20f1",
    "a06771c16809dc05cb64358579e383342b6de6782fcf558d637e613349c4cc4b1f8eb66952f132e2845f136796538a64",
    "5f1e3aef3ffdf034c061eaca48ef91bb0193d01280d591c36886689f3ff9c55470bb68435ea6e4d588de32be48d88709",
    "a58ce332edf468a56ea96aa2e0a87cb2356665a67ca64b1e070c407eeb34bb50b731881706f085f8c3fdd832507731cf",
    "616b8cca99ffb9cacb3c8d277837f28ef0e13872a64814df1e5b690ca49ba537374cda262d15c8adf5bcd73702080191",
    "7ee7246bdd851c01f1d3dda0f1824cf7559bddef8f6237f0eb895d02062d0301e59377ebe484bd8092868ecde41e5acd",
    "a31912886f1be0e895f16132d0be979d61d800c56ec64b2d5cbc7edcec73caf3974eaf77a7317021e2cfa4a57a5cea0a",
    "94bf177bc66c5c05b46617630c362be02a9cef253cc0259f5be2db6e1f5118377d5e2ebb6a4017bd6883592f97ccae50",
    "561ddf037ebf5fcfad4106c54735d9b80e7ab5d476abbdf9670bb69b9499179523df8088b035050631f0164201a10aa2",
    "3d89475bd9bf20a7b9e14a40fca2f2d52aa61af47b33b89eedd9f1a44d8c8452fdffb57d32d879a72e4f0ede1dc89ee3",
    "e40b0e52de8ea0e72db91c869c9395f5a813b575657fdfbd84b347c421d44a67d9061550d7babff3f6c99ec5c35b4cff",
    "5d1026064b44892bcc9dd25bdf261ffd3af045eedc30d061d367a96a9301b2a3927e3da7dcdd0fe11b17bb68b9a95df8",
    "cba8e4e1367f204f65880d87cfb4439a5fd2dbf379ff86e3396ce9d86c4eca33c48c242ef50efc65958c708bfd843126",
    "27946fc6177a363d13aaf888a6f1bf6fd0707385b16efca7ccbac97e24e7a7a60f26373ba9a7c2593d2736bc96d1d392",
    "af65b8a2f65e98d36c807484549bb8b113854d867e0a32d69185123f4cf5c7c8ad24d688c448ce0771ca7e70ad2988bc",
    "ccde7a55d033dc72184c5a12d409f07e791c68be75a008cfa9c953fce7b7d3bde8bdd2a0e85456fcdc708ce433c7eb52",
    "e36ea41afc901958b080afb4b09644883b28b571530769338daca20b41d0b2db21d4a00d763bb8752c0bad397a53438f",
    "9e1eb6262cbdf1071acc02c5c0136ab3a3889cb290c1ba2e001cf7dd0604644a41867ae356c89ee5f44c5b1e9f332a63",
    "89de2ee0da2b90d4335f39cd0147a8223e9146042ef89e12a41bbdc20aa89e79ca33adda0faf650dd3d08b7dc06eba0b",
    "b9e9c44c02ca4456661b138d26aee1e08c23700850133c77729994563e4aab73acc24b496acca429bc7213471108ce6e",
    "4778dc9a377f1abd7451fdf7bbac2ebbad757dbca7669d68ac42bd9bb908ea07cd2f884f7ef4d97d9bd6c91f5d5f2324",
    "0c8e4b52f2efb7c666bffad705b883f37a97dc35747efbd60b14aabf7578058e3e00b9569b982ebd83c073fda445619d",
    "1865122db43b838c1a8986738b079b2651ce251535b147136990a675955f8c425ea7d6660685372f9e904a9cb82c6c82",
    "9a9715de00289ddb8fb19ab72d7ef68d5c410d2edff4444c3d5179af9a9c10b8dc2356ceb304817d12b58d7a79985f68",
    "e5eeb39c6d6be52a72f5563de31a1c944225ec5e4fd0ac8dc8d34df537a8d4adf1ddf7dd3804af9a94490789caf0f92f",
    "097fb6cb9dad182badede05cb79ce239a5ebcd3b23c78f567e7cee26a27df903b0ebe5630995e6ee842dbe63fb421137",
    "908c17f891ec7bc805d5672da5a42aefb1340b0ba8f84f1e1b9e8d7cec3a8e1a40b090ffad175107c13592c6c02d55ad",
    "ab1d6ec0a5c4cdb4ca6b6973f47c3eddde614c69474913db04d4fa147aa0006e45af3471b2833c9ebcca42fa377c8e6d",
    "c67bb22f493817838f83a22eab51b9518c50c5f27825843b8f268889b17373dd7a78ab67a58a550ec85f4799ba94d8ca",
    "dd8b2452557b8b7611e28346faecebc8e9c804b1595ecbd5b872e76db4a5d618e780b62b804aaedfa70701eb8de8312d",
    "36f206095a17217a066d96510e23aec27618cf8c217eaff718b1550847a8ee6b2a31aa0844ec6e7861bedd17607cd146",
    "24bfdc983a4213c7b1dd2aa815748c7c08661a480eef36ce82382724b7d017ccc71acbd8279dc6b2f0f520ea1fea9a56",
    "4ac69d261430ea98cc404bc4ce21a32d5d20affa9b9a9e08262a79fc893f92ae1abd2b1196bb5815c38e8cb12e04c532",
    "a4a1d7596b1769cd08624ca20a3a8f6a617395bcb0e137d6021c5b2d9df83b74fe949f0d4ac9311d589edec598679717",
    "bcd4c1392b6128593df4ddefd4e23def0ec009a22b2dfb0ec6e820d0a86865b1e623cdf04cf455f9233202c9c3e2287d",
    "eea0b7184fad49efe2843e4c53541be9ee89d95cafa7e112f99e9e5dd29ffefa72c0c73600560da17823be67eed20891",
    "37e0793a13483e4271f95e98d505a1ef35cd6f07a1810024525b078b63a9482bf7416fea962503c6087553f43288e6d8",
    "90d961f38fced9b40f1dd6c643cf1648fbef023d69024334b31bf934b4347e3ffa147db02a7ac17624eda068fb57f977",
    "89caba0012c980293307579bd0a516cc92473e8dae8e7ef83beaaf230dcd6306852d4e58439a2bdeafbd75f9008969d9",
    "87cf69a5ac99f623ebbf003e8d1e1020485b3113be460cd13b52df8ec040e7161dd96a7d52ed594fb04855231d28633c",
    "463b9683629383681d0d6401e62e2abb219dd3a1fc310171a24e6691704771ec3903344e0e2778ce310f1995cd45a03f",
    "9e4fd862dcc2b1593689ce1b66828c534832df158b8b6c93ba8141db233dbbb4c6e2ccb50255be0a86acd3bf8bf5886b",
    "f89ab1f1b1be727a3d34a7901a91764c038e77b2ee2b203f735e25b1c5978d357a79e6f4bf1aa93fd78747e46c3ecfbb",
    "9ad7b8da969f74a1459e2e89b2b8b1668d1b4e4439e3a33a41253ed0ef95b984d22d802f64ce2f28167681e3d32a3238",
    "c1667c9b9a515d62c8a9b0622ecb7c9149ff222095486b5edceb70337f7cc2c506f4177f8e8304c704a1781204c7a3b3",
    "67ef97002c1a55156b8fbd10a746f103e4ac0aeed90f1bdc7d0a4cb12da658fc3ad0ccf006b3efc7f05e7ae4955f169e",
    "ca6b6c9d9863467acd5e9d5a3e6a9675b08d0413a2361f1e0afea886c53b68f388b75d1d1a39a0d981aa062f0d81b579",
    "7c71f11aabb2f35b2672adf948dc08b0fd9a1910a50a80621b0aee41f811d681d85b160badabd8f5a1183d2dce69b8b7",
    "51dde17353cd82db2e8de6ac88d27922a119b6806ef13f8ec9ae4d463687c097b4f98333d1e167ac09e6b0b6d27c2efd",
    "4b03ea07d3ac78ceff10ecba9a95d19ec710f8141df494a83f46285df5c536f7e067db9a41f25af318eeca057c40ccf0",
    "d89e6e27ad1b0c92804059944bef23a73949b58163480aa164c814350f950189db4e31da05a213cd34d2f4b7aeaa0cf1",
    "61ed108d4b8167c495ac3e48a6b3d325c570eddb23465f5b620853d2aec9c44c289f06071f24437191e8eff84092b2b8",
    "c0193b5cb9d9e7eeff417b848793b5b6b9dae7fb1c37538cadc4f1355873cffd0000000000000000000a0f1722292e",
  ].join("");

const RETIRED_Q_TEST_NET_1_REGISTRATION = {
  tx_id: "QTX12XCH3FRGH3TS3GDFYLMYY6Z0URFP8S0TPG9FJ74CVMH86W7GQN5QCTUXLE",
  from: "Q1U7HUE7868S0MDHWK4NUPE8YWGP6ZRC3G9JXN429VJP8G5M3VPSWSLEL3CX",
  scheme: 1,
  raw: RETIRED_Q_TEST_NET_1_REGISTRATION_RAW,
  signature: RETIRED_Q_TEST_NET_1_REGISTRATION_RAW.slice(-2 * ML_DSA_65_SIGNATURE_BYTES),
};

function requireNativeMlDsa() {
  assert.ok(
    nativeMlDsaAvailable(),
    "this Node build has no native ML-DSA-65, run the labs on Node 24 or later so the signature is verified rather than measured"
  );
}

test(`the ${LIVE_NETWORK} chain id is the first 8 bytes of SHA3 256 of its name, offline`, () => {
  assert.equal(chainIdFor(LIVE_NETWORK), LIVE_NETWORK_CHAIN_ID);
  assert.notEqual(chainIdFor(RETIRED_NETWORK), LIVE_NETWORK_CHAIN_ID);
});

function sha3(bytes) {
  return createHash("sha3-256").update(bytes).digest();
}

function u64le(n) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(n));
  return out;
}

function encodeBody(p) {
  const fee = Buffer.alloc(16);
  fee.writeBigUInt64LE(p.fee & ((1n << 64n) - 1n), 0);
  fee.writeBigUInt64LE(p.fee >> 64n, 8);
  const field = (bytes) => Buffer.concat([u64le(bytes.length), bytes]);
  return Buffer.concat([
    field(p.sender),
    u64le(p.nonce),
    u64le(p.meterLimit),
    fee,
    field(p.target),
    field(p.args),
    u64le(p.value),
    u64le(p.chainId),
    field(p.inAsset),
    u64le(p.validUntil),
    Buffer.from([p.kind]),
  ]);
}

function signedRegistration(chainId, genesis, change = {}) {
  const template = RETIRED_Q_TEST_NET_1_REGISTRATION;
  const trailer = 1 + 8 + ML_DSA_65_SIGNATURE_BYTES;
  const shape = parseTransactionBody(Buffer.from(template.raw, "hex").subarray(0, template.raw.length / 2 - trailer));
  assert.ok(shape.target.equals(KEY_REGISTER_TARGET) && shape.kind === 0, "the recorded registration is sent to the key registration system address as a transfer");
  const { publicKey, privateKey } = generateKeyPairSync("ml-dsa-65");
  const pk = publicKey.export({ format: "der", type: "spki" }).subarray(-ML_DSA_65_PUBLIC_KEY_BYTES);
  const sender = change.sender || sha3(Buffer.concat([Buffer.from([SCHEME_ML_DSA_65]), pk]));
  const args = change.pad ? Buffer.concat([pk, Buffer.alloc(1)]) : pk;
  const body = encodeBody({ ...shape, sender, args, chainId, target: change.target || shape.target, kind: change.kind ?? shape.kind });
  const signature = sign(null, sha3(Buffer.concat([genesis, body])), { key: privateKey, context: Buffer.from(TRANSACTION_CONTEXT) });
  const raw = Buffer.concat([body, Buffer.from([SCHEME_ML_DSA_65]), u64le(signature.length), signature]);
  return {
    tx_id: encodeBech32m("QTX", sha3(raw)),
    from: encodeBech32m("Q", sender),
    scheme: SCHEME_ML_DSA_65,
    raw: raw.toString("hex"),
    signature: signature.toString("hex"),
  };
}

test(`a key registration signed for ${LIVE_NETWORK} verifies only under its chain id and genesis, offline`, () => {
  requireNativeMlDsa();
  const live = chainIdFor(LIVE_NETWORK);
  const genesis = randomBytes(32);
  const tx = signedRegistration(live, genesis);
  assert.equal(transactionChainId(tx), live);
  const verdict = verifyKeyRegistration(tx, live, genesis);
  assert.ok(verdict.ok, verdict.reason);
  assert.equal(verifyKeyRegistration(tx, live, randomBytes(32)).ok, false, "a registration must not verify over another genesis");
  assert.equal(verifyKeyRegistration(tx, live).ok, false, "a registration signed over a genesis must not verify without it");
  const retired = signedRegistration(chainIdFor(RETIRED_NETWORK), genesis);
  const refused = verifyKeyRegistration(retired, live, genesis);
  assert.equal(refused.ok, false);
  assert.match(refused.reason, new RegExp(`bound to chain id ${chainIdFor(RETIRED_NETWORK)}, not ${live}`));
  const flipped = tx.raw.slice(0, 200) + (tx.raw[200] === "0" ? "1" : "0") + tx.raw.slice(201);
  assert.equal(verifyKeyRegistration({ ...tx, raw: flipped }, live, genesis).ok, false);
  const forged = { ...tx, signature: "ab".repeat(ML_DSA_65_SIGNATURE_BYTES) };
  forged.raw = tx.raw.slice(0, -2 * ML_DSA_65_SIGNATURE_BYTES) + forged.signature;
  assert.equal(verifyKeyRegistration(forged, live, genesis).ok, false, "a signature of the right length but wrong content must not pass");
  const transfer = signedRegistration(live, genesis, { target: sha3(Buffer.from("an ordinary recipient")) });
  assert.match(verifyKeyRegistration(transfer, live, genesis).reason, /key registration system address/, "a transfer that carries the key must not pass as a registration");
  const call = signedRegistration(live, genesis, { kind: 1 });
  assert.match(verifyKeyRegistration(call, live, genesis).reason, /kind 1/, "a call to the registration address must not pass as a registration");
  const foreign = signedRegistration(live, genesis, { sender: sha3(Buffer.from("an account the key does not belong to")) });
  assert.match(verifyKeyRegistration(foreign, live, genesis).reason ?? "", /does not hash to the sender address/, "a key that does not hash to the sender must not pass even when its signature verifies");
  const padded = signedRegistration(live, genesis, { pad: true });
  assert.equal(verifyKeyRegistration(padded, live, genesis).ok, false, "the arguments must be exactly the registered key");
});

test(`a retired ${RETIRED_NETWORK} key registration is refused for ${LIVE_NETWORK}, offline`, () => {
  requireNativeMlDsa();
  const retired = RETIRED_Q_TEST_NET_1_REGISTRATION;
  assert.equal(transactionChainId(retired), chainIdFor(RETIRED_NETWORK));
  const verdict = verifyKeyRegistration(retired, chainIdFor(LIVE_NETWORK));
  assert.equal(verdict.ok, false, `a ${RETIRED_NETWORK} registration must not verify for ${LIVE_NETWORK}`);
  assert.equal(verifyKeyRegistration(retired, chainIdFor(RETIRED_NETWORK), randomBytes(32)).ok, false, "a registration signed without a genesis must not verify over one");
  assert.match(verdict.reason, new RegExp(`bound to chain id ${chainIdFor(RETIRED_NETWORK)}, not ${chainIdFor(LIVE_NETWORK)}`));
  const raw = retired.raw;
  const flipped = raw.slice(0, 200) + (raw[200] === "0" ? "1" : "0") + raw.slice(201);
  const tampered = verifyKeyRegistration({ ...retired, raw: flipped }, chainIdFor(RETIRED_NETWORK));
  assert.equal(tampered.ok, false);
  assert.doesNotMatch(tampered.reason, /chain id/);
  const forged = { ...retired, signature: "ab".repeat(ML_DSA_65_SIGNATURE_BYTES) };
  forged.raw = raw.slice(0, -2 * ML_DSA_65_SIGNATURE_BYTES) + forged.signature;
  assert.equal(verifyKeyRegistration(forged, chainIdFor(RETIRED_NETWORK)).ok, false, "a signature of the right length but wrong content must not pass");
});

async function findKeyRegistration(g) {
  if (NAMED_KEY_REGISTRATION_ID) {
    const tx = await g.getTransaction(NAMED_KEY_REGISTRATION_ID);
    assert.ok(tx?.tx_id === NAMED_KEY_REGISTRATION_ID, "the gateway returned another transaction");
    assert.ok(tx.kind === "key_register", `${printable(NAMED_KEY_REGISTRATION_ID)} is not a key registration`);
    return tx;
  }
  const head = await g.headHeight();
  let lookups = 0;
  for (let i = 1; i <= WINDOW && i <= head; i += 1) {
    const block = await g.getBlock(head - i);
    for (const id of Array.isArray(block?.tx_ids) ? block.tx_ids : []) {
      if (lookups >= MAX_LOOKUPS) break;
      lookups += 1;
      const tx = await g.getTransaction(id);
      if (tx?.kind === "key_register" && tx.tx_id === id) return tx;
    }
  }
  throw new Error(`no key registration was found in the last ${WINDOW} blocks, set QUANTOVA_KEY_REGISTER_TX to name one`);
}

test("live, a key registration served by the chain verifies under the key it registers", { skip }, async () => {
  requireNativeMlDsa();
  const g = new QuantovaGateway();
  const { genesis } = await g.binding();
  const tx = await findKeyRegistration(g);
  const verdict = verifyKeyRegistration(tx, chainIdFor(EXPECTED_CHAIN_ID), genesis);
  assert.ok(verdict.ok, verdict.reason);
  console.log(`ML-DSA-65 signature of ${printable(tx.tx_id)} verified under the key bound to ${printable(tx.from)} on ${printable(EXPECTED_CHAIN_ID)} and its pinned genesis`);
});

async function fetchSignedTransaction(g) {
  const head = await g.headHeight();
  for (let i = 1; i <= WINDOW && i <= head; i += 1) {
    const block = await g.getBlock(head - i);
    const id = block?.tx_ids?.[0];
    if (id) return g.getTransaction(id);
  }
  throw new Error(`no transaction was found in the last ${WINDOW} blocks`);
}

test("a chain signature is in the post quantum size band", { skip }, async () => {
  const g = new QuantovaGateway();
  const tx = await fetchSignedTransaction(g);
  const sigHex = tx.signature;
  assert.ok(typeof sigHex === "string" && /^[0-9a-f]+$/.test(sigHex), "the transaction carries no hex signature");
  const expected = Object.hasOwn(CHAIN_SIGNATURE_BYTES, tx.scheme) ? CHAIN_SIGNATURE_BYTES[tx.scheme] : null;
  assert.ok(expected !== null, `the transaction names signature scheme ${printable(tx.scheme)}, the chain signs with scheme 1 for ML-DSA-65 or scheme 2 for SLH-DSA`);
  const { bytes, classical, postQuantum, nearest } = classifySignature(sigHex);
  assert.equal(bytes, expected, `the signature is ${bytes} bytes, a scheme ${printable(tx.scheme)} signature is exactly ${expected} bytes`);
  const trailer = Buffer.alloc(9);
  trailer[0] = tx.scheme;
  trailer.writeBigUInt64LE(BigInt(bytes), 1);
  assert.ok(typeof tx.raw === "string" && tx.raw.endsWith(trailer.toString("hex") + sigHex), "the signature does not close the transaction bytes the chain recorded");

  console.log(`signature length ${bytes} bytes, nearest post quantum parameter set ${nearest}`);

  assert.ok(
    !classical,
    `signature is ${bytes} bytes, within the classical band at or below ${CLASSICAL_MAX_BYTES}. ` +
      "A post quantum chain must not authenticate with 64 byte ECDSA or Ed25519 signatures."
  );
  assert.ok(
    postQuantum,
    `signature is ${bytes} bytes, below the post quantum minimum of ${PQ_MIN_BYTES}. ` +
      "Quantova signs with ML-DSA-65 at 3309 bytes or SLH-DSA at 16224 bytes."
  );
});
