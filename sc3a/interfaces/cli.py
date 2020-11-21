import logging
from typing import Text

from argparse import ArgumentParser

from sc3a.analysis.base import AnalysisStrategy
from sc3a.analysis.strategies.single_owner import SingleOwnerStrategy
from sc3a.loader.contract_loader_factory import get_factory, LoaderFactoryType

log = logging.getLogger(__name__)


def parse_cli_args() -> AnalysisStrategy:
    program_name = 'SC3A - Smart Contract Advanced Administrator Analyzer'
    parser = ArgumentParser(description=program_name)
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='print detailed output')

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-b', '--bin', metavar='PATH', type=Text, dest='bin_path', help='path to file containing EVM bytecode')
    input_group.add_argument('-s', '--sol', metavar='PATH', type=Text, dest='sol_path', help='path to solidity contract')
    input_group.add_argument('-a', '--address', metavar='ADDRESS', type=Text, dest='address', help='contract address to analyze')

    networking_group = parser.add_argument_group('networking arguments')
    networking_group.add_argument('--rpc', metavar="RPC", type=Text, dest='rpc', help='web3 HTTP(s) provider URL')

    args = parser.parse_args()

    # Set logging level to DEBUG for all logers if verbose option was specified
    if args.verbose:
        for logger in [logging.getLogger(name) for name in logging.root.manager.loggerDict]:
            logger.setLevel(logging.DEBUG)

    # Get the contract loader factory and strategy based on the specified options
    # TODO: Needs to be improved, the latest when the strategy loader is introduced
    if args.bin_path:
        factory = get_factory(LoaderFactoryType.BINARY, path=args.bin_path)
        strategy = SingleOwnerStrategy.from_file_loader(factory.create())
    elif args.sol_path:
        factory = get_factory(LoaderFactoryType.SOLIDITY, path=args.sol_path)
        strategy = SingleOwnerStrategy.from_file_loader(factory.create())
    elif args.address:
        factory = get_factory(LoaderFactoryType.WEB3, address=args.address, rpc=args.rpc)
        strategy = SingleOwnerStrategy.from_web3_loader(factory.create())
    else:
        raise NotImplementedError('This feature hasn\'t been implemented yet')

    return strategy


def main():
    strategy = parse_cli_args()
    log.info('Results: %s', str(strategy.execute()))
