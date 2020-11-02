# Smart Contract Advanced Administrator Analyzer (SC3A)

## Requirements

- Python 3.6+
- [Mythril Python Library](https://github.com/ConsenSys/mythril)

Installing Mythril:

```bash
$ pip3 install mythril
```

Alternatively create a virutalenv and install mythril there.

## Executing

```
$ cd <directory to project root>
$ ./sca --help

usage: sca [-h] [-v] (-b PATH | -s PATH | -a ADDRESS) [--rpc RPC]

SC3A - Smart Contract Advanced Administrator Analyzer

optional arguments:
  -h, --help            show this help message and exit
  -v                    print detailed output
  -b PATH, --bin PATH   path to file containing EVM bytecode
  -s PATH, --sol PATH   path to solidity contract
  -a ADDRESS, --address ADDRESS
                        contract address to analyze

networking arguments:
  --rpc RPC             web3 provider
```
