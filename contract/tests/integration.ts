import axios from "axios";
import { Wallet, SecretNetworkClient, TxResponse } from "secretjs";
import fs from "fs";
import assert from "assert";

// Returns a client with which we can interact with secret network
const initializeClient = async (endpoint: string, chainId: string) => {
  const wallet = new Wallet(); // Use default constructor of wallet to generate random mnemonic.
  const accAddress = wallet.address;
  const client = new SecretNetworkClient({
    // Create a client to interact with the network
    url: endpoint,
    chainId: chainId,
    wallet: wallet,
    walletAddress: accAddress,
  });

  console.log(`Initialized client with wallet address: ${accAddress}`);
  return client;
};

// Stores and instantiaties a new contract in our network
const initializeContract = async (
  client: SecretNetworkClient,
  contractPath: string
) => {
  const wasmCode = fs.readFileSync(contractPath);
  console.log("Uploading contract");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasm_byte_code: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
      gasLimit: 5000000,
    }
  );

  if (uploadReceipt.code !== 0) {
    console.log(
      `Failed to get code id: ${JSON.stringify(uploadReceipt.rawLog)}`
    );
    throw new Error(`Failed to upload contract`);
  }

  const codeIdKv = uploadReceipt.jsonLog![0].events[0].attributes.find(
    (a: any) => {
      return a.key === "code_id";
    }
  );

  const codeId = Number(codeIdKv!.value);
  console.log("Contract codeId: ", codeId);

  const contractCodeHash = (await client.query.compute.codeHashByCodeId({code_id: String(codeId)})).code_hash;

  if (contractCodeHash === undefined) {
    throw new Error(`Failed to get code hash`);
  }

  console.log(`Contract hash: ${contractCodeHash}`);

  const contract = await client.tx.compute.instantiateContract(
    {
      sender: client.address,
      code_id: codeId,
      init_msg: { },
      code_hash: contractCodeHash,
      label: "My contract" + Math.ceil(Math.random() * 10000), // The label should be unique for every contract, add random string in order to maintain uniqueness
    },
    {
      gasLimit: 1000000,
    }
  );

  if (contract.code !== 0) {
    throw new Error(
      `Failed to instantiate the contract with the following error ${contract.rawLog}`
    );
  }

  const contractAddress = contract.arrayLog!.find(
    (log) => log.type === "message" && log.key === "contract_address"
  )!.value;

  console.log(`Contract address: ${contractAddress}`);

  const contractInfo: [string, string] = [contractCodeHash, contractAddress];
  return contractInfo;
};

const getFromFaucet = async (address: string) => {
  await axios.get(`http://localhost:5000/faucet?address=${address}`);
};

async function getScrtBalance(userCli: SecretNetworkClient): Promise<string> {
  let balanceResponse = await userCli.query.bank.balance({
    address: userCli.address,
    denom: "uscrt",
  });

  if (balanceResponse?.balance?.amount === undefined) {
    throw new Error(`Failed to get balance for address: ${userCli.address}`)
  }

  return balanceResponse.balance.amount;
}

async function fillUpFromFaucet(
  client: SecretNetworkClient,
  targetBalance: Number
) {
  let balance = await getScrtBalance(client);
  while (Number(balance) < targetBalance) {
    try {
      await getFromFaucet(client.address);
    } catch (e) {
      console.error(`failed to get tokens from faucet: ${e}`);
    }
    balance = await getScrtBalance(client);
  }
  console.error(`got tokens from faucet: ${balance}`);
}

// Initialization procedure
async function initializeAndUploadContract() {
  let endpoint = "http://localhost:1317";
  let chainId = "secretdev-1";

  const client = await initializeClient(endpoint, chainId);
  // we'll need 2 players for the game
  const client2 = await initializeClient(endpoint, chainId);

  await fillUpFromFaucet(client, 100_000_000);
  await fillUpFromFaucet(client2, 100_000_000);

  const [contractHash, contractAddress] = await initializeContract(
    client,
    "contract.wasm"
  );

  var clientInfo: [SecretNetworkClient, SecretNetworkClient, string, string] = [
    client,
      client2,
    contractHash,
    contractAddress,
  ];
  return clientInfo;
}

async function queryGameState(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string,
  gameCode: string,
): Promise<string> {
  type GameStateResponse = { state: string };

  const countResponse = (await client.query.compute.queryContract({
    contract_address: contractAddress,
    code_hash: contractHash,
    query: { game_state: { game: gameCode } },
  })) as GameStateResponse;

  if ('err"' in countResponse) {
    throw new Error(
      `Query failed with the following err: ${JSON.stringify(countResponse)}`
    );
  }

  return countResponse.state;
}


async function initializeGame(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddess: string
) {
  const tx: TxResponse = await client.tx.compute.executeContract(
    {
      sender: client.address,
      contract_address: contractAddess,
      code_hash: contractHash,
      msg: {
        new_game: { player_name: "alice" },
      },
      sent_funds: [],
    },
    {
      gasLimit: 200000,
    }
  );

  console.log(`initializeGame TX used ${tx.gasUsed} gas`);

  return tx;
}

// The following functions are only some examples of how to write integration tests, there are many tests that we might want to write here.
async function test_query_initial_status(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string,
  gameCode: string
) {
  const result: string = await queryGameState(
    client,
    contractHash,
    contractAddress,
      gameCode
  );
  assert(
      result === "WaitingForPlayerToJoin",
    `Status was ${result}, even though the game should be waiting for 2nd player"`
  );
}

async function test_initialize_game(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string
) {
  let tx = await initializeGame(client, contractHash, contractAddress);

  let gameCode = ""
  for (const k in tx.jsonLog[0].events) {
    console.log(tx.jsonLog[0].events[k].type)
    if (tx.jsonLog[0].events[k].type.toLocaleLowerCase() === 'wasm-new_rps_game') {
      for (const attrIdx in tx.jsonLog[0].events[k].attributes) {
        if (tx.jsonLog[0].events[k].attributes[attrIdx].key.toLocaleLowerCase() === 'game_code') {
          gameCode = tx.jsonLog[0].events[k].attributes[attrIdx].value
        }
      }
    }
  }

  console.log(`Got game code: ${gameCode}`)

  assert(
      gameCode !== "",
    `Didn't get a new game code! This is the tx response: ${JSON.stringify(tx)}`
  );

  return gameCode;
}

async function test_gas_limits() {
  // There is no accurate way to measue gas limits but it is actually very recommended to make sure that the gas that is used by a specific tx makes sense
}

async function runTestFunction<R>(tester: CallableFunction): Promise<R> {
  // @ts-ignore
  console.log(`Testing ${tester.name}`);
  let resp: R = await tester();
  // @ts-ignore
  console.log(`[SUCCESS] ${tester.name}`);

  return resp;
}

(async () => {
  const [client, client2, contractHash, contractAddress] =
    await initializeAndUploadContract();

  let gameCode = await runTestFunction<string>(
      test_initialize_game.bind(this, client, contractHash, contractAddress),
  );

  await runTestFunction(
    test_query_initial_status.bind(this, client, contractHash, contractAddress, gameCode),
  );

})();
