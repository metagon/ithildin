# Ithildin

<p align="center">
    <img src="assets/ithildin_logo.png" height="400px" />
</p>

> Ithildin was a type of specially crafted Mithril that only the most experienced craftsmen of the Noldor could learn how to make and pass on to others.

Ithilding is a semantic analyzer for Smart Contracts based on [Mythril](https://github.com/ConsenSys/mythril).
By using symbolic execution and taint analysis, it aims at detecting functions that are restricted by authentication patterns, and to extract administrator addresses whenever possible.

The [Aniron](https://thehutt.de/tolkien/fonts/aniron/readme.html) font is Copyright &copy; Pete Klassen, 2004. All rights Reserved.

## Requirements

- Python 3.6+
- [Mythril Python Library](https://github.com/ConsenSys/mythril)

## Setup

Install all the requirements inside a virtual environment or globally.

### Installing Mythril Inside a Virtual Environment (Recommended)

```bash
$ cd <ithildin-root-dir>
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
```

### Installing Mythril Globally

Install the latest version using the following command.
Note that ithildin might not work in case breaking changes have been introduced to the library.

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
$ cd <ithildin-root-dir>
```

### Analyzing Solidity Contracts

```bash
$ ./ithil --sol Example.sol --solc <solc-binary>
```

### Analyzing Bytecode Files

The EVM bytecode has to be the creation bytecode, meaning that the constructor has to be present.
Contracts that have been deployed on the chain have that part removed post-construction.
If you want to analyze the bytecode of a deployed contract use the next option.

```bash
$ ./ithil --bin Example.bin
```

### Analyzing Deployed Contracts

The following command analyzes the contract bytecode at the given target address.
You'll have to supply the RPC endpoint using the `--rpc` argument, unless you are using geth, in which case the default endpoint `http://localhost:8545` is used.

```bash
$ ./ithil --address 0x3D8e04CC42F61624e1B193C51f27D373A9244D9b --rpc localhost:7545
```
