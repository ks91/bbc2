Ledger subsystem with Ethereum for BBc-2
===
Files in this directory supports the ledger subsystem with Ethereum blockchain for BBc-2.
Currently supports brownie, with infura.io to access to goerli test network and mainnet of Ethereum.

## Ledger subsystem
* **bbc2/serv/ethereum/bbc_ethereum.py**
  * abstraction of BBcAnchor smart contract that would store Merkle roots of documents.
  * also provides setup library functions for brownie environment and to use infura.io projects.
  * also provides verify function that takes a Merkle subtree for independent verification from BBc-1 or BBc-2.
* **bbc2/serv/ethereum/contracts/BBcAnchor.sol**
  * The BBcAnchor smart contract.
* **utils/bbc_eth_tool.py**
  * sets up brownie environment and to use infura.io projects to access Ethereum networks. See usage below.

## Dependencies
* eth-brownie>=1.19.3 (pip-installed)
* solc (solidity) 0.5 (install with apt or brew) (actual compilation uses py-solc-x installed with brownie, but requires depedencies for solc anyway)

## How to use
For the example below, we assume that BBc-2 is pip-installed, and 'bbc_serv.py' is running at the user's home directory (the "config.json" file resides under "~/.bbc2"). The default Ethereum network is goerli test network.

1. Set up brownie environment
```
$ bbc_eth_tool.py -w ~/.bbc2 brownie <infura.io project ID>
```

2. Set up a new Ethereum account (if you do not have one yet)
```
$ bbc_eth_tool.py -w ~/.bbc2 new_account
```
If you have already got an account, and know its private key, you can set it using "account" command of bbc_eth_tool.py.

3. Load the account with ETH from the specified network

For that, for goerli, faucets like https://goerlifaucet.com can be used. The balance can be confirmed with "balance" command of bbc_eth_tool.py.

4. Deploy BBcAnchor smart contract
```
$ bbc_eth_tool.py -w ~/.bbc2 deploy
```

You are all set, and you can run ledger_subsystem with enabled=True argument or enable() it. Or you may want to try "enable" command of bbc_eth_tool.py for that.

If you are sure, then you may want to try
```
$ bbc_eth_tool.py -w ~/.bbc2 auto <infura project ID> <private_key>
```
to automatically set up everything with an existing Ethereum account with sufficient ETH balance at the specified network (but beware that the contract address will be overwritten. Consider this as a testing feature, useful when BBc-2 configuration has been erased).

You do not need to set up an account or deploy the contract again.
The information is all written into the config file of BBc-2.

## Tests
* **tests/test_bbc_ethereum1.py**
* **tests/test_bbc_ethereum2.py**
* **tests/test_bbc_ethereum3.py**
* **tests/test_ledger_subsystem.py**
