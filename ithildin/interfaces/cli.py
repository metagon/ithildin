import logging

from argparse import ArgumentParser
from typing import Text, Union

from ithildin.analysis.symbolic import LaserWrapper
from ithildin.loader.contract_loader_factory import get_factory, LoaderFactoryType
from ithildin.loader.contract_loader import FileLoader, JsonRpcLoader


def parse_cli_args() -> Union[FileLoader, JsonRpcLoader]:
    program_name = 'Ithildin - Semantic analyzer of EVM bytecode based on Mythril'
    parser = ArgumentParser(description=program_name)
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='print detailed output')
    parser.add_argument('--timeout', metavar='SEC', type=float, default=60, dest='timeout', help='symbolic execution timeout')
    parser.add_argument('--json', action='store_true', dest='as_json', help=('print report as JSON to standard output '
                                                                             '(this option supresses all logging)'))

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-b', '--bin', metavar='PATH', type=Text, dest='bin_path', help='path to file containing EVM bytecode')
    input_group.add_argument('-s', '--sol', metavar='PATH', type=Text, dest='sol_path', help='path to solidity contract')
    input_group.add_argument('-a', '--address', metavar='ADDRESS', type=Text, dest='address', help='contract address to analyze')

    networking_group = parser.add_argument_group('networking arguments')
    networking_group.add_argument('--rpc', metavar="RPC", type=Text, dest='rpc', help='JSON RPC provider URL')

    compilation_group = parser.add_argument_group('compilation arguments')
    compilation_group.add_argument('--solc', metavar='SOLC', type=Text, dest='solc', help='solc binary path', default='solc')

    args = parser.parse_args()

    # Set logging level to DEBUG for all logers if verbose option was specified
    # Disable logging propagation in case the *--json* flag was specified
    if args.verbose or args.as_json:
        for logger in [logging.getLogger(name) for name in logging.root.manager.loggerDict]:
            if args.verbose:
                logger.setLevel(logging.DEBUG)
            if args.as_json:
                logger.propagate = False

    # Get the contract loader factory based on the specified options
    if args.bin_path:
        contract_loader_factory = get_factory(LoaderFactoryType.BINARY, path=args.bin_path)
    elif args.sol_path:
        contract_loader_factory = get_factory(LoaderFactoryType.SOLIDITY, path=args.sol_path, solc=args.solc)
    elif args.address:
        contract_loader_factory = get_factory(LoaderFactoryType.JSON_RPC, address=args.address, rpc=args.rpc)
    else:
        raise NotImplementedError('This feature hasn\'t been implemented yet')

    return contract_loader_factory.create(), args


def main():
    contract_loader, args = parse_cli_args()
    symbolic_analysis = LaserWrapper()
    report = symbolic_analysis.execute(contract_loader=contract_loader, timeout=args.timeout)
    print(report.to_json(pretty=True) if args.as_json else report.to_text())
