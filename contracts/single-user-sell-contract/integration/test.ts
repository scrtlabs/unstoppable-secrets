import * as fs from "fs";
import {
  coinsFromString,
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
        key_gen: {
          encrypted_user_signing_key:
            "0QQAAAAAAAAzODc0ODQ0NTYzNjUwNjYzMDYwMTIyMDI4MDE5MTg4MDQwMTM4NjA5OTA3NzAyNjUzMDA0NDA5ODI5MjU2NjcxNjQ0MDU1MjQxMzQyOTQ2NjYxMDE1NDgyNDA0NjI3NzA2ODE2MTYxNDk3OTY1MzE4NTA1MDMxMDYwNTg2ODA1NjQ5MzY2MzY0MjQ5NzkyMjQwNDI3MTgwNzY4OTg3NzEzMTkzOTc2MjY4NzQyMTI5MTM0ODI2MTMyMTMxMjg4OTgwNDY4NTUxMzIxMzU4NTEwODcxNjA2NDExNzU1MjEzNDc5MjIxNzc4MDAzNDY1MDg0MjM0NjI2MDYwMTU4NDYxODAwNjcyMTQ5ODQ3MDU2ODg0NzYwMTg0MjQ3ODY4NzMzODcxMjEyMTU1MTExMDY4NDA2NzQxNDU4ODgwODE0NjAxMTk5OTI4OTk1OTMxNDkxNTA2ODk0MTQzNjIyODQxMDM0NTkyOTk4MjE0ODM3ODk3MDg1MDYzOTk5ODE3ODA4ODM2MjU0NDk5MzIzOTE1MzQ2MDQ3NzQ2ODI1MDkzODQ0ODMzODI5MDYyNjkwNDQ0ODQ1Mjg5NjUyNzk5NTg1NDk2MTEwMTk2MjM3MTAxNTA5ODQzNDY3OTA5MTk4OTIwNzk3NDMwMjU0NDkxMjA4NzkwNjAwOTQ0NTI3NjQwMjU5ODQ4NzMxMDk5NjAzNjg0MjU5NTA0ODkxODM1MjkzMDA4NDMwNzk2MDY3NzA1OTk1ODY0NzY5OTEwNTQ0MjI1Mjg2NDc5Njg4OTIzMjcwODA2NzExNDA1Nzc3NjUxNTQxNDI0MzYwODIyNDI3MDkyODkwODUxNTczNzE4NjM0ODE0OTc3NzE5MDMzNjI4MjI3NjE0MDA5NTE5MDQxODAyODk1OTkwNjQ0NjkyOTI5ODg5ODk1NTk1NzUzNTkzMzIwMDYxMDA3MDk1NTg2MDM2NzM0NzEzMjIyNzA4MDYyNTQzMjI4ODg4MTM5NzAyMzI1NzI5MDgwNTc2Nzk3ODQ2MDk3Nzg0OTc3ODU2NDExNDAyMDg2NDE4ODY3ODE3MTQ4NTY5MTUxMzQ0MTA5NTYyMzAyMzIyMjcyOTM4NTYwNDk1NjQyODYxMzc5MTk1ODk2NDQwNjk4NTM5MTU0OTY0MDE4OTEzMTE3MTYyMDUxNzU2NDM1OTAzNDQwNzIwMTgwMTk2NTYyNDY5NTY2MzQ1MzAyNzY4NTE1ODg2NzU1NTM3NTQ5MDMyMzk3ODEyNTE2ODA4Njc5Njg2NTM3MzYzNDQwNTQ1NDQ1ODE1NzUxOTU1NDczNzEzNjMxNjk1NTMyNzgzNjAwMzc4Nzg0NDIxOTMzOTQyODU0ODIyMzIyODExNzAyNDgxMjI3NTQxMjI4MDk1MTkxMzAyNTM5ODc3MTk0OTA3MTc1NzA0OTg3ODk0Mjc0MDkwNDQxMDU4MjQ3NDIzMjY3Nzg0NjMzMDcyMjE4NTg1NzgyODI1ODYxMTgwMzc5NDE1MTM4MDcyNTg1MDkyNzg5NzEzNDg1Mzc5ODQ2MzgwNDk0NzAxNTQ1OTIwNDMxNjY1NzMxNjk1OTc3MDAyMTk5MzQ1Mjg5NTU5NDA0OTA5MzQyNDQ0MjM0MzE0MjgyNzk3MzY5ODQwMjEBAAAAAAAAAA==",
          public_signing_key_user:
            "QAAAAAAAAABAAAAAAAAAAJuDJ9kpoORShcBNGcn/++4GXCZrcBlyki2AcigSDkPzStaKx39uwCBf4598W2BV2tlzoDRko6dDMC3g/q9uxtk=",
          enc_public_key:
            "aQIAAAAAAAAyMzY3NzMwMzk4NDEyOTE1ODMyMzU0OTAwMTc0MTA4NjI3NzkzNTA0NjI3ODUxODUyMTIwMjY3NDk5MTYxNDc3OTA4NzIzNDA2MjI3NTQ2MDAzNTg3NzU4ODMwNDM1MDU3MTU0Mzg4MjQwNTc1NzUwMTUzNjk0MDU1MTEzNTMwMDkwMDM0MTg3MjY2OTk2NjU2NzMxMTA1NDk4ODAyMzQ2NjY2MTU5NDQyMDE4NDYyMTQ2MzE4Mzk1NDg5ODUwNTgxODEwMDE5ODg4Njg1MTM1MjQwMzc0NDgxNjQ1ODQ4MzgzNTYyNTgxOTIwOTI0MjUxMTkwMTcwNjk5MTYwNDkxODcyMTg4Nzk4MzI1MDExNTIzOTc3OTA1MzkxMTY4NTYzOTIxMjUzMzY1MzU2NjM5ODc2NTA2NTQ5NzcxMTI5Mzg1OTk3MjI3NzY2OTU5Mjc5NjQ4NzA2MTYxNTg1NzczOTIzMDYyMjQ5MTk5MzEyOTU4NDk0Nzc2ODYxNjgwNDkyNjIwOTMzNjMxNDg3MzUzNzU4MDQ2MDc4ODA5OTc1NjIwNTY5Mzc5MTk2NTgyNDUwNjc2Mjk4ODM1MTE4Mzg3NjgwMTk3OTAyMDA5NjI5Nzc0MTUxNTUyNzExNjc0Njk1Njg2MTkwMzIxMjg1MTI2OTE5ODY0OTMxODc4MzY2NDIwMjczNDAxOTI3NzA2OTg1NDQ1Njc5MzI5NTU2OTUwNzcwNTIwODY3NzYwNzE2NjIyMDQ0MDY5NzQ1MTQ1OTUzNTAzMjU3ODIzNDIzNzkwNTQxOTA1OTY5MDI1Njc4NDQ4NDk5NjQ1Nw==",
        },
      },
      label: String(Date.now()),
    },
    { gasLimit: 1_000_000 }
  );

  if (tx.code !== 0) {
    console.log(tx.rawLog);
  }
  expect(tx.code).toBe(0);

  console.log("keygen gas:", tx.gasUsed);

  const { address: contract_address, data: public_signing_key_chain_bytes } =
    MsgInstantiateContractResponse.decode(tx.data[0]);

  tx = await secretjs.tx.compute.executeContract(
    {
      sender: secretjs.address,
      contract_address,
      msg: {
        sign: {
          message_hash:
            "1111111111111111111111111111111111111111111111111111111111111111",
          public_instance_key_user:
            "ef16dd7c75ca40cfeab2aa659f2201e857591df3de67494a4d1dae34587395e65423081f56a54362ae66f53d04c083878f156111f071805f971cf03adcc775a9",
          proof: "",
          commitment: "",
          seed: 3,
        },
      },
    },
    { gasLimit: 2_000_000 }
  );

  if (tx.code !== 0) {
    console.log(tx.rawLog);
  }
  expect(tx.code).toBe(0);

  console.log("sign gas:", tx.gasUsed);

  tx = await secretjs.tx.compute.executeContract(
    {
      sender: secretjs.address,
      contract_address,
      sent_funds: coinsFromString("1uscrt"),
      msg: {
        bid: {
          buyer_enc_public_key:
            "aQIAAAAAAAAxNTY4MDQ2OTc3MzQ0NDUzOTA3MzkxOTEyMDA0MzQyMzIyODg1MjU2MTU0ODg0OTg1NjI1MDU0NDQxMDA4OTY2MjQ4NTM4NjMyNzAyNjIxMDM1OTEzNDQ3NDY4Mjg1NDA1MjY2ODI4MzU0OTk3NjQwOTE0Njk1MTYxNjIzNDUxNTMzOTkzNTIxMTAxMzUwMzMzMzU5OTIwMzM0NDEyNTY2ODQwMzg5Mjc0NTI4NTU5MDcwNzU4MzU1MTczNzQwNjE0NTYzNzczMzcwNTI1Njg0NTQ2Mjk2OTI1MzEwMDYxMzQ5NDIxNTk5ODg2NTMwNzYwMTA0MTU1NzE4Mzg5ODg2NTgyOTA4MTM4Nzg4ODk1OTIxMzg5MTA2NzY2NTU4MDU5NDU1MzQ0MTcwNTM1NjIwNTY0NTk2MDc0MjQ4NjU2NjE3NjExNjQ0NzY0NTY4ODkxNzQ1MjA3NzU0NTc5MjkzNzIzODI4MDU2ODkyNjQ5NTM2OTgwMTc4NzA5NDUxNzUwOTI5ODE0MzgyODI2MzQyMDk2NzU5MDM1ODg2NDY3NzM1MjU4ODgyNDkzODQ1MjYzNTM5NTEyMDg4OTQwMDQ0MzA2NTI3NTc0Mjg1NjU1MTgxNTM5MjE3ODY1ODc5NDk2MTEwMDU1MzM0NTYxNDI4NDM4MjgxMTkzMzM2NjY0ODQ2MjcwOTY5Mjc5MjE5NTkzNDQ2MTY0NjQ2ODg3NTU4NzU4NjY2NjQxNTQzNDQwMTQ4MjA0NjI1NjcwNzk4MzA5OTUxNTkzOTYwNzMwNzUxNjI4NDQ3Mzc2NzcyMjgzMDg4NTMyMjUwMQ==",
          proof: "",
        },
      },
    },
    { gasLimit: 2_000_000 }
  );

  if (tx.code !== 0) {
    console.log(tx.rawLog);
  }
  expect(tx.code).toBe(0);

  console.log("bid gas:", tx.gasUsed);

  tx = await secretjs.tx.compute.executeContract(
    {
      sender: secretjs.address,
      contract_address,
      msg: {
        sell: {
          encrypted_buyer_signing_key:
            "0QQAAAAAAAAyMDQyMjgxNTI5OTQzNzA3Njc5ODcxMTQxMzU1MTc1OTEyNzYwNDYzNTM5ODY0MDQyODQyOTM5Mzc2NjI0MjM1NDkyNDExMzY3NjE5ODc5NzgwNDE5NTM2Mzc3MTU5Mjk0NDIzMDM1OTAzMjgyMDcwMjQ5MDY1Njk2NjgwNDg1MzUyOTA4OTU2NTg4NTI1MDk1MDQyMzQzMzkwNzgxOTEzMzI4MTQ4NDcxMzA3NDY0MTQxMDc3MjY1NDkwOTA5MTA4MzE1NTUxMzg0MjU1MzAyODgwNTA5MzQ0ODk0Nzk3NTQ4MTE2OTI2MTUwMzAwMDg2NDczMzA5OTY3MTU0OTA2NTI1NTM1OTE3ODI3OTk3MTM5NDg4NDEyNDEyMTE2Njc2NDA2ODEzNzQ4MjI3MzgwNDMzODczOTA2NjI5OTUwNzAwMDgwNjk2MTAwMzQ0MDQ0NzAyODM3NTQzNDk4OTA5Mzk1NzkxNDg0NTU1MTM1MTA0NDM4ODExNjk4ODIxMDYwNzU1NTk0OTE1NzMyNzA1ODc3NTE1OTEwODMyNTI4NDA4NDQ3OTU4MjczOTAxMTc2OTM3OTMxMTU0NTA0OTE2ODYzMjY1Njk0NDE0NTg4MDYxMzM3NTAzODI1OTA1NDQ3NDY5MDcwNjI1ODYyNzAyMzgyMzcyOTM5MDE1MjUyMzU4OTgwNjU0NzgyMDM5OTQxMjA1MjI0Mzk1NDQ5NzcyNTM2ODE4MDQ1OTE3OTgwMTI1NzM3OTAxMzM4MTI2NTgxOTUwODUyOTQ1MjI1NDAzNzE3MjU5MTYyMjY0MTU4MzE3NzU2MjkwNjM1Nzk4NjI4NzcwNTcwMzg5MTgwNTAxOTg3NTAzMTMxNjIyMzIxMTEyNDI3MjU3ODA2MDkwMzE4NTI1NTYxODc3NTM0OTE2ODE1OTExMDE4MjQ2NDQwOTcxMjA0NjMxNDIxODQ1Mzc5OTQ5ODUwNTc3MTQyNTA2NDY5MDM5ODI2ODU0NDA5NTAyODMwNTA4OTcyNzM1MTIzMjc2MTgxMzI5Njk4MDk3NTIwNTMwNTIxMzI3MjgzNTEyMzcwMDI1NTQxNzgwMDczNTI1ODg1OTg2MTgwNjY0MzE4ODQyNTM1MDg3MTMyOTcyMTk1ODIyMjI2MzU5OTA3MjE2NjE2ODU1ODg4OTMwNTA2OTk4Mjk5ODUyOTg3NzA2NTE3ODkyMjc5MzQ4ODE4Nzk0NDUxNzcwNTI3NzUwNzg1OTc3NTg4NTc4MzM3MjMwNDUxMDIxNDEzNDQ0Mjg5NjA2OTIzNzQ3MjAyMjY1ODExOTQ0NDg1MDY4OTUxNDYwNjA1NTgwMzIzMTQwODk3ODI4ODI5ODgwOTIzMTk2MzMyODEwOTM1NTU4OTgyMDkzMTY5MDA5MjYyMzQ4MTcyOTQ3MjQyMDcyMzI2MzQ3NTc4NjMzNTE0MDY4MjA1MjA5MDk4NTAzODUyMDgxODk2NjY0MDQwODM3ODU5NzIxODE0NjUyNjUwOTIwNDAxNTk3Nzc2Njk0NjA2NjQ5NzU3NDc4NjY4Mzg3MzM0ODM2OTg5OTAxMjA0ODcyNjg5NTg4NTc4MDE3MTM4ODI5NDE4NjQzNDgxOTg2MzQ4NjUzMDA5NTg4Mjg3OTU0ODU2MzIBAAAAAAAAAA==",
          buyer_enc_public_key:
            "aQIAAAAAAAAxNTY4MDQ2OTc3MzQ0NDUzOTA3MzkxOTEyMDA0MzQyMzIyODg1MjU2MTU0ODg0OTg1NjI1MDU0NDQxMDA4OTY2MjQ4NTM4NjMyNzAyNjIxMDM1OTEzNDQ3NDY4Mjg1NDA1MjY2ODI4MzU0OTk3NjQwOTE0Njk1MTYxNjIzNDUxNTMzOTkzNTIxMTAxMzUwMzMzMzU5OTIwMzM0NDEyNTY2ODQwMzg5Mjc0NTI4NTU5MDcwNzU4MzU1MTczNzQwNjE0NTYzNzczMzcwNTI1Njg0NTQ2Mjk2OTI1MzEwMDYxMzQ5NDIxNTk5ODg2NTMwNzYwMTA0MTU1NzE4Mzg5ODg2NTgyOTA4MTM4Nzg4ODk1OTIxMzg5MTA2NzY2NTU4MDU5NDU1MzQ0MTcwNTM1NjIwNTY0NTk2MDc0MjQ4NjU2NjE3NjExNjQ0NzY0NTY4ODkxNzQ1MjA3NzU0NTc5MjkzNzIzODI4MDU2ODkyNjQ5NTM2OTgwMTc4NzA5NDUxNzUwOTI5ODE0MzgyODI2MzQyMDk2NzU5MDM1ODg2NDY3NzM1MjU4ODgyNDkzODQ1MjYzNTM5NTEyMDg4OTQwMDQ0MzA2NTI3NTc0Mjg1NjU1MTgxNTM5MjE3ODY1ODc5NDk2MTEwMDU1MzM0NTYxNDI4NDM4MjgxMTkzMzM2NjY0ODQ2MjcwOTY5Mjc5MjE5NTkzNDQ2MTY0NjQ2ODg3NTU4NzU4NjY2NjQxNTQzNDQwMTQ4MjA0NjI1NjcwNzk4MzA5OTUxNTkzOTYwNzMwNzUxNjI4NDQ3Mzc2NzcyMjgzMDg4NTMyMjUwMQ==",
          proof: "",
          payment_address: secretjs.address,
        },
      },
    },
    { gasLimit: 2_000_000 }
  );

  if (tx.code !== 0) {
    console.log(tx.rawLog);
  }
  expect(tx.code).toBe(0);

  console.log("sell gas:", tx.gasUsed);
});
