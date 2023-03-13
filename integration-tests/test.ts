import { ec } from "elliptic";
import * as fs from "fs";
import {
  coinsFromString,
  MsgInstantiateContractResponse,
  MsgStoreCodeResponse,
  SecretNetworkClient,
  stringToCoins,
  TxResultCode,
  Wallet,
} from "secretjs";
import util from "util";

export const exec = util.promisify(require("child_process").exec);

export async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitForChain(account: Account) {
  const secretjs = new SecretNetworkClient({
    url: "http://localhost:1317",
    chainId: "secretdev-1",
    wallet: account.wallet,
    walletAddress: account.address,
  });

  while (true) {
    try {
      const tx = await secretjs.tx.bank.send({
        amount: coinsFromString("1uscrt"),
        from_address: account.address,
        to_address: account.address,
      });

      if (tx.code === TxResultCode.Success) {
        break;
      }
    } catch (e) {
      // console.error(e);
    }
    await sleep(250);
  }
}

type Account = {
  address: string;
  mnemonic: string;
  wallet: Wallet;
  secretjs: SecretNetworkClient;
};

const accounts: Account[] = [];

let contract_address: string;

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

  await waitForChain(accounts[0]);

  // set block time to 300ms
  await exec(
    `docker exec localsecret sed -E -i '/timeout_(propose|prevote|precommit|commit)/s/[0-9]+m?s/100ms/' .secretd/config/config.toml`
  );
  await exec(`docker restart localsecret`);

  await waitForChain(accounts[0]);
}, 1000 * 60 * 60);

test("benchmark", async () => {
  const { secretjs } = accounts[0];

  let tx = await secretjs.tx.compute.storeCode(
    {
      sender: secretjs.address,
      wasm_byte_code: fs.readFileSync(
        `${__dirname}/../contract.wasm.gz`
      ) as Uint8Array,
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

  for (let n = 2; n < 16; n++) {
    for (let t = 1; t < n; t++) {
      tx = await secretjs.tx.compute.instantiateContract(
        {
          sender: secretjs.address,
          code_id,
          init_msg: {
            number_of_users: n,
            signing_threshold: t,
          },
          label: String(Date.now()),
        },
        { gasLimit: 1_000_000 }
      );

      if (tx.code !== 0) {
        console.log(tx.rawLog);
      }
      expect(tx.code).toBe(0);

      console.log(
        `${n},${t},init,${
          JSON.stringify({
            number_of_users: n,
            signing_threshold: t,
          }).length
        },${tx.gasUsed}`
      );

      contract_address = MsgInstantiateContractResponse.decode(
        tx.data[0]
      ).address;

      let input = fs.readFileSync(
        `${__dirname}/../contract/${n}_${t}_keygen.json`,
        {
          encoding: "utf-8",
        }
      );
      tx = await secretjs.tx.compute.executeContract(
        {
          sender: secretjs.address,
          contract_address,
          msg: JSON.parse(input),
        },
        { gasLimit: 1_000_000 }
      );

      if (tx.code !== 0) {
        console.log(tx.rawLog);
      }
      expect(tx.code).toBe(0);

      console.log(`${n},${t},keygen,${input.length},${tx.gasUsed}`);

      input = fs.readFileSync(
        `${__dirname}/../contract/${n}_${t}_presign.json`,
        {
          encoding: "utf-8",
        }
      );
      tx = await secretjs.tx.compute.executeContract(
        {
          sender: secretjs.address,
          contract_address,
          msg: JSON.parse(input),
        },
        { gasLimit: 1_000_000 }
      );

      if (tx.code !== 0) {
        console.log(tx.rawLog);
      }
      expect(tx.code).toBe(0);

      console.log(`${n},${t},presig,${input.length},${tx.gasUsed}`);

      input = fs.readFileSync(`${__dirname}/../contract/${n}_${t}_sign.json`, {
        encoding: "utf-8",
      });
      tx = await secretjs.tx.compute.executeContract(
        {
          sender: secretjs.address,
          contract_address,
          msg: JSON.parse(input),
        },
        { gasLimit: 1_000_000 }
      );

      if (tx.code !== 0) {
        console.log(tx.rawLog);
      }
      expect(tx.code).toBe(0);

      console.log(`${n},${t},sign,${input.length},${tx.gasUsed}`);
    }
  }
});
