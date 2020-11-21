# Smart Contract Advanced Administrator Analyzer (SC3A)

## Requirements

- Python 3.6+
- [Mythril Python Library](https://github.com/ConsenSys/mythril)

## Setup

Install all the requirements inside a virtual environment or globally.

### Installing Mythril inside a virtual environment (recommended)

```bash
$ cd <sc3a-root-directory>
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
```

### Installing Mythril globally

Install the latest version using the following command.
Note that SC3A might not work in case breaking changes have been introduced to the library.

```bash
$ pip3 install mythril
```

Preferably, install the working dependencies with:

```bash
$ pip3 install -r requirements.txt
```

## Analyzing Contracts

Since no install script is present yet, you'll need to navigate to the project's root directory for now.

```bash
$ cd <sc3a-root-dir>
```

### Analyzing Solidity contracts

```bash
$ ./sca --sol Example.sol
```

### Analyzing bytecode

The EVM bytecode has to be the creation bytecode, meaning that the constructor has to be present.
Contracts that have been deployed on the chain have that part removed post-construction.
If you want to analyze the bytecode of a deployed contract use the next option.

```bash
$ ./sca --bin Example.bin
```

### Analyzing deployed contracts

The following command analyzes the contract bytecode at the given target address.
You'll have to supply the RPC endpoint using the `--rpc` argument, unless you are using geth, in which case the default endpoint `http://localhost:8545` is used.

```bash
$ ./sca --address 0x3D8e04CC42F61624e1B193C51f27D373A9244D9b --rpc localhost:7545
```
