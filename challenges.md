# Shamir Secret Sharing

The goal was to sign an Ethereum transaction using Shamir's Secret Sharing (SSS). The most challenging part was implementing the Ethereum signing process, which involves encoding the transaction bytes as RLP, hashing them with Keccak256 to create a message to sign, using SSS to sign it, and encoding the signature with the raw transaction using Ethereum's RLP - all done on-chain.

The idea was for the user to pass all values to the contract, which would encode the transaction and generate the signature.

For the MVP, the aim was to make legacy transactions (pre EIP-1559) work. However, the transaction encoding method is immaterial here and can be generalized to every type of transaction out there (Bitcoin, Cosmos, Ethereum's EIP-1559, etc.).

## Anatomy of a (legacy) Etherutm transaction

- `nonce`: This is an integer value that is incremented with each transaction sent from a given account. It is used to ensure that each transaction can only be executed once, in order to prevent replay attacks.
- `gas_price`: This is the amount of Wei (the smallest denomination of ether) that the sender is willing to pay per unit of gas used in the transaction. Miners can choose which transactions to include in blocks based on a variety of factors, including the gas price, so setting a higher gas price can help ensure that your transaction is processed more quickly.
- `gas`: This is the maximum amount of gas that can be used in the transaction. Gas is used to pay for the computational resources required to execute the transaction on the Ethereum network. If the transaction requires more gas than the limit specified in the `gas` field, the transaction will fail.
- `to`: This is the address of the recipient of the transaction, or the contract that the transaction should be executed against. If the `to` field is set to `null` or `0x0`, it is a contract creation transaction.
- `value`: This is the amount of ether to transfer in Wei. If the `value` field is set to `0`, it is a contract call transaction rather than a value transfer transaction.
- `data`: This is optional input data to pass to the contract being executed, if any. If this field is not used, it should be set to `0x`.
- `chain`: This is the ID of the chain on which to execute the transaction. This field is used in the transaction signature in conjunction with the `nonce` field to prevent replay attacks. If not specified, the default chain ID is `1` for the Ethereum mainnet.

The `from` field of an Ethereum transaction specifies the account that is sending the transaction. It is not included in the data of the transaction, but can be derived using some steps as follow:

1. Recover the public key of the account that signed the transaction
2. Decompress the public key if compressed (compressed = 33 bytes; decompressed = 65 bytes).
3. Convert the resulting decompressed public key to its raw form (64 bytes).
4. Compute the Keccak256 hash of the raw public key.
5. Take the lower 20 bytes (which represent the last 40 characters in the hex string form) of the resulting hash as the `from` address.

Here is a pseudo code to demonstrate how to derive the `from` field:

```js
pubkey = secp256k1_recover_pubkey(tx_signature);
decompressed_pubkey = secp256k1_decompress_pubkey(pubkey);
raw_pubkey = secp256k1_pubkey_to_raw(decompressed_pubkey);
hash = keccak256(raw_pubkey);
from = last_20_bytes(hash);
```

## Making stuff work

We attempted to use both the `tx-from-scratch` and `ethereum-tx-sign` crates. Fortunately, both options allow us to encode transaction bytes in RLP, generate the transaction hash required for signing, sign the transaction using a private key, and output the signed transaction ready to be broadcast on the Ethereum chain. We chose to use the `ethereum-tx-sign` crate, as it also offers support for EIP-1559 transactions too (for future work). However, we faced an issue as we did not have the private key for signig, as it was split using SSS. Therefore, we had to extract the encoding code from the `ethereum-tx-sign` crate, create the signature `(v,r,s)` ourselves, and encode the final transaction ourselves.

We used the following tools to validate and try to broadcast our transactions:

- https://flightwallet.github.io/decode-eth-tx/
- https://app.mycrypto.com/broadcast-transaction
- https://etherscan.io/pushTx

### Invalid signature

While using the tools above, we quickly realized that something was not okay with our signature. We assumed that the issue was with the `v` value, as local testing showed that the signature `(r,s)` verified correctly.

However, the correct way of calculating `v` was buried in (Stack Overflow comments)[https://ethereum.stackexchange.com/a/118342/12112] which eventually lead us to (EIP-155)[https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#specification]. The mistake we made was calculating `v` for EIP-1559 while trying to send legacy transations.

After fixing the issue with the `v` value, we still noticed that:

1. About 80% of the transactions we generated failed to validate on the above tools, giving `invalid sender` as the error.
2. Out of the valid transactions we produced, none were able to enter the Ethereum mainnet mempool.

### Invalid sender

> About 80% of the transactions we generated failed to validate on the above tools.

While 100% of our generated transactions verified offline using the `secp256k1` crate, they failed to verify using the above Ethereum tools. This indicated that an Ethereum-specific transformation is needed to be applied to the signature to make it valid. Moreover, the `invalid sender` error displayed by the Ethereum tools was less than helpful.

Upon inspecting https://app.mycrypto.com/broadcast-transaction through the Chrome dev tools, we discovered a more verbose error: `s out of range`. A Google search led us to a [helpful internet stranger](https://github.com/ethers-io/ethers.js/issues/1224#issuecomment-756604768) and [EIP-2](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md), which states that `s` must be positive. Once we applied the [following fix](https://github.com/scrtlabs/unstoppable-secrets/commit/31ed6e47eb9eb5896432521aea84ecbf93af0d51), all our transactions were able to validate correctly on the Ethereum tools:

```js
if (s < 0) {
  s = s.modular_inverse();
}
```

### Entering the mempool

> Out of the valid transactions we produced, none were able to enter the Ethereum mainnet mempool.

We successfully used Ethereum tools to broadcast transactions on Ethereum mainnet. However, we encountered issues when trying to locate these transactions on Etherscan or in the mempool. Increasing the gas price or attempting to send more than 1 wei did not solve the problem.

To try and address this issue, we switch to signing EIP-1559 `FeeMarketTransaction` with our SSS signing scheme. This required us to adjust once again the way we calculate the `v` value. Despite our efforts with different values of `max_fee_per_gas`, `max_priority_fee_per_gas` & `value`, we were still unable to broadcast a transaction that would register in the mempool.

As a last resort, we reverted to `LegacyTransaction` (EIP-155) and attempted to send a transaction with `nonce = 0`. To our surprise, this transaction worked, as seen in the following link: https://etherscan.io/tx/0x58a7bd4863fc0e004ef6e1b0719cbd0e50f468752a1de4483dd68a888462e497. Notice the exceptionally high `gas_price` of 1,140 Gwei, compared to the 13 Gwei at the time of the transaction, and the `value` of 0.001 ETH, which was approximately $1.8 at that time.

It is worth noting that nonce traditionally refers to a random number used only once in cryptography. However, in this case, it refers to a running number that increments with each transaction sent by the account. We have been unable to locate where `nonce` is defined to start at `0` in the Ethereum EIPs documentation, and we will continue to investigate this matter. (TODO Assaf: find it in the docs and rephrase this paragraph)

# On-chain Paillier encryption
