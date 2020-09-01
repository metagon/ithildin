import logging
from typing import Text

from argparse import ArgumentParser
from mythril.ethereum.evmcontract import EVMContract

from sc3a.analysis.strategies.single_owner import SingleOwnerStrategy
from sc3a.loader.contract_loader_factory import get_factory, LoaderFactoryType

log = logging.getLogger(__name__)

program_name = 'SC3A - Smart Contract Advanced Administrator Analyzer'
parser = ArgumentParser(description=program_name)
parser.add_argument('-v', action='store_true', dest='verbose',
                    help='print detailed output')

input_group = parser.add_mutually_exclusive_group(required=True)
input_group.add_argument('-b', '--bin', metavar='PATH', type=Text, dest='bin_path',
                         help='path to file containing EVM bytecode')
input_group.add_argument('-s', '--sol', metavar='PATH', type=Text, dest='sol_path',
                         help='path to solidity contract')
input_group.add_argument('-a', '--address', metavar='ADDRESS', type=Text, dest='address',
                         help='contract address to analyze')

networking_group = parser.add_argument_group('networking arguments')
networking_group.add_argument('--rpc', metavar="RPC", type=Text,
                              dest='rpc', help='web3 provider')

args = parser.parse_args()

# Set logging level to DEBUG for all logers if verbose option was specified
if args.verbose:
    for logger in [logging.getLogger(name) for name in logging.root.manager.loggerDict]:
        logger.setLevel(logging.DEBUG)

# Get the contract loader factory based on the specified options
if args.bin_path:
    factory = get_factory(LoaderFactoryType.BINARY, path=args.bin_path)
elif args.sol_path:
    factory = get_factory(LoaderFactoryType.SOLIDITY, path=args.sol_path)
else:
    raise NotImplementedError('This feature hasn\'t been implemented yet')


def main():
    loader = factory.create()
    strategy = SingleOwnerStrategy(loader.contract())
    log.info('SingleOwner results: %s', str(strategy.execute()))
