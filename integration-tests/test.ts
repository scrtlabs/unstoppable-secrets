import { ec } from "elliptic";
import * as fs from "fs";
import {
  fromBase64,
  MsgInstantiateContractResponse,
  MsgStoreCodeResponse,
  SecretNetworkClient,
  toHex,
  Wallet,
} from "secretjs";
import * as sss from "sssa-js";

const secp256k1 = new ec("secp256k1");

export async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitForBlocks(chainId: string) {
  const secretjs = new SecretNetworkClient({
    url: "http://localhost:1317",
    chainId,
  });

  console.log(`Waiting for blocks on ${chainId}...`);
  while (true) {
    try {
      const { block } = await secretjs.query.tendermint.getLatestBlock({});

      if (Number(block?.header?.height) >= 1) {
        console.log(`Current block on ${chainId}: ${block!.header!.height}`);
        break;
      }
    } catch (e) {}
    await sleep(100);
  }
}

type Account = {
  address: string;
  mnemonic: string;
  wallet: Wallet;
  secretjs: SecretNetworkClient;
};

const accounts: Account[] = [];

let contract: string;

beforeAll(async () => {
  jest.spyOn(console, "warn").mockImplementation(() => {});

  const mnemonics = [
    "grant rice replace explain federal release fix clever romance raise often wild taxi quarter soccer fiber love must tape steak together observe swap guitar",
    "jelly shadow frog dirt dragon use armed praise universe win jungle close inmate rain oil canvas beauty pioneer chef soccer icon dizzy thunder meadow",
    "chair love bleak wonder skirt permit say assist aunt credit roast size obtain minute throw sand usual age smart exact enough room shadow charge",
    "word twist toast cloth movie predict advance crumble escape whale sail such angry muffin balcony keen move employ cook valve hurt glimpse breeze brick",
  ];

  // Create clients for all of the existing wallets in secretdev-1
  for (let i = 0; i < mnemonics.length; i++) {
    const mnemonic = mnemonics[i];
    const wallet = new Wallet(mnemonic);
    accounts.push({
      address: wallet.address,
      mnemonic: mnemonic,
      wallet: wallet,
      secretjs: new SecretNetworkClient({
        url: "http://localhost:1317",
        wallet: wallet,
        walletAddress: wallet.address,
        chainId: "secretdev-1",
      }),
    });
  }

  await waitForBlocks("secretdev-1");

  const wasmBytes = fs.readFileSync(
    `${__dirname}/../contract.wasm.gz`
  ) as Uint8Array;

  console.log("Storing contract on-chain...");

  const { secretjs } = accounts[0];

  let tx = await secretjs.tx.compute.storeCode(
    {
      sender: secretjs.address,
      wasm_byte_code: wasmBytes,
      source: "",
      builder: "",
    },
    { gasLimit: 2_000_000 }
  );

  if (tx.code !== 0) {
    console.log(tx.rawLog);
  }
  expect(tx.code).toBe(0);

  const { code_id } = MsgStoreCodeResponse.decode(tx.data[0]);

  tx = await secretjs.tx.compute.instantiateContract(
    {
      sender: secretjs.address,
      code_id,
      init_msg: {
        number_of_users: 7,
        signing_threshold: 2,
      },
      label: String(Date.now()),
    },
    { gasLimit: 1_000_000 }
  );

  if (tx.code !== 0) {
    console.log(tx.rawLog);
  }
  expect(tx.code).toBe(0);

  contract = MsgInstantiateContractResponse.decode(tx.data[0]).address;
}, 90_000);

type Share = {
  id: number;
  data: string; // hex string
  threshold: number;
  share_count: number;
};

describe("KeyGen", () => {
  test("happy path", async () => {
    const { secretjs } = accounts[0];

    const keyPair = secp256k1.genKeyPair();
    const pubkeyHex = keyPair.getPublic("hex").slice(2); // raw pubkey
    const privkeyHex = keyPair.getPrivate("hex");

    const rawShares = sss.create(2, 9, privkeyHex);
    const parsedShares: Share[] = rawShares.map((share: string, i: number) => ({
      id: i + 1,
      data: "0000000000000000000000000000000000000000000000000000000000000000" /* toHex(
        fromBase64(share.substring(0, 44).replace(/_/g, "/").replace(/-/g, "+"))
      ) */,
      threshold: 2,
      share_count: 9,
    }));

    const tx = await secretjs.tx.compute.executeContract(
      {
        sender: secretjs.address,
        contract_address: contract,
        msg: {
          key_gen: {
            user_public_key: pubkeyHex, // raw pubkey - 64 bytes
            user_secret_key_shares: parsedShares,
          },
        },
      },
      { gasLimit: 1_000_000 }
    );

    if (tx.code !== 0) {
      console.log(tx.rawLog);
    }
    expect(tx.code).toBe(0);

    console.log("Keygen gas:", tx.gasUsed);
  });

  test.skip("e.g. wrong user_public_key format", async () => {});

  test.skip("e.g. wrong user_secret_key_shares", async () => {});
});

describe("CreatePresig", () => {
  test.skip("happy path", async () => {});

  test.skip("e.g. wrong user_index", async () => {});

  test.skip("e.g. wrong k_user_shares", async () => {});

  test.skip("e.g. wrong a_user_shares", async () => {});

  test.skip("e.g. wrong user_zero_shares1", async () => {});

  test.skip("e.g. wrong user_zero_shares2", async () => {});

  test.skip("e.g. wrong public_instance_key", async () => {});
});

describe("Sign", () => {
  test.skip("happy path", async () => {});

  test.skip("e.g. wrong user_index", async () => {});

  test.skip("e.g. wrong user_sig_num_share", async () => {});

  test.skip("e.g. wrong user_sig_denom_share", async () => {});
});
