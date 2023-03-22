import * as fs from "fs";
import {
  MsgInstantiateContractResponse,
  MsgStoreCodeResponse,
  SecretNetworkClient,
  Wallet,
} from "secretjs";

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

let code_id: string;

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
    `${__dirname}/../contract.wasm`
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

  ({ code_id } = MsgStoreCodeResponse.decode(tx.data[0]));
}, 90_000);

test("gm", async () => {
  const { secretjs } = accounts[0];

  let tx = await secretjs.tx.compute.instantiateContract(
    {
      sender: secretjs.address,
      code_id,
      init_msg: {
        encryption_key: "qwe",
      },
      label: String(Date.now()),
    },
    { gasLimit: 1_000_000 }
  );

  if (tx.code !== 0) {
    console.log(tx.rawLog);
  }
  expect(tx.code).toBe(0);

  const contract_address = MsgInstantiateContractResponse.decode(
    tx.data[0]
  ).address;

  tx = await secretjs.tx.compute.executeContract(
    {
      sender: secretjs.address,
      contract_address,
      msg: {
        encrypted_c1: "asd",
        encrypted_c2: "zxc",
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
