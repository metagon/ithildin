# Ithildin

![Ithildin Logo](https://raw.githubusercontent.com/metagon/ithildin/master/assets/ithildin_logo.png)

![GitHub](https://img.shields.io/github/license/metagon/ithildin?color=blue)
![PyPI](https://img.shields.io/pypi/v/ithildin)
![PyPI - Status](https://img.shields.io/pypi/status/ithildin)

> Ithildin was a type of specially crafted Mithril that only the most experienced craftsmen of the Noldor could learn how to make and pass on to others.

Ithildin is a semantic analysis tool for EVM bytecode based on [Mythril](https://github.com/ConsenSys/mythril).
By using symbolic execution and taint analysis, it aims at detecting functions that are restricted by authentication patterns, and to extract administrator addresses whenever possible.

Check out the wiki for a list of currently working patterns and some that are planned to be implemented soon.

The [Aniron](https://thehutt.de/tolkien/fonts/aniron/readme.html) font is Copyright &copy; Pete Klassen, 2004. All rights Reserved.

## Requirements

- Python 3.6+

## Installation

```bash
$ pip3 install ithildin
```

## Executing

Ithildin can currently analyze contracts provided in one of the following formats.
Run `ithil --help` to see all arguments that the program accepts.

### Deployed Contracts

The following command analyzes the contract bytecode at the given target address.
You'll have to supply the RPC endpoint using the `--rpc` argument, unless you are using geth, in which case the default endpoint `http://localhost:8545` is used.

> **Note:** Infura secrets are currently not supported.

```bash
# Using a local JSON RPC provider
$ ithil analyze --address 0x3D8e04CC42F61624e1B193C51f27D373A9244D9b --rpc localhost:7545
# Using an Infura provider
$ ithil analyze --address 0x868326efca6e89f75a76d141167759f1ad10854c --rpc https://mainnet.infura.io/v3/<project-id>
```

### Solidity Contracts

This command will use the solc compiler that is currently installed on your system if `--solc` is not specified.
Older compilers can be downloaded from the [ethereum/solc-bin](https://github.com/ethereum/solc-bin) repository (make sure you make them executable).

```bash
# Using solc version v0.7.6
$ ithil analyze --sol Example.sol --solc solc-linux-amd64-v0.7.6+commit.7338295f
```

### Creation Bytecode Files

Provide a file containing the EVM (creation) bytecode in one line.

```bash
$ ithil analyze --bin Example.bin
```

## Development Setup

Install all the requirements inside a virtual environment or globally.

### Installing Mythril Inside a Virtual Environment (Recommended)

```bash
$ cd <ithildin-root>
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
```

### Installing Mythril Globally

```bash
$ pip3 install -r requirements.txt
```
