import logging

from argparse import ArgumentParser
from typing import Text, Union

from ithildin import __version__
from ithildin.analysis.symbolic import LaserWrapper
from ithildin.contract.loader import FileLoader, JsonRpcLoader
from ithildin.contract.loader_factory import get_factory, LoaderFactoryType

DEFAULT_MAX_DEPTH = 128
DEFAULT_RPC = 'http://127.0.0.1:8545'
DEFAULT_SOLC = 'solc'
DEFAULT_TIMEOUT = 60


def parse_cli_args() -> Union[FileLoader, JsonRpcLoader]:
    program_name = 'Ithildin - EVM bytecode semantic analysis tool based on Mythril'
    parser = ArgumentParser(description=program_name)
    parser.add_argument('--version', action='version', version='Ithildin v{}'.format(__version__))
    parser.add_argument('--verbose', action='store_true', help='print debugging output')
    parser.add_argument('--json', action='store_true', dest='as_json',
                        help=('print report as JSON to standard output (this option supresses all logging)'))

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-a', '--address', metavar='ADDRESS', type=Text, help='contract address to analyze')
    input_group.add_argument('-s', '--sol', metavar='PATH', type=Text, dest='sol_path', help='path to solidity contract')
    input_group.add_argument('-b', '--bin', metavar='PATH', type=Text, dest='bin_path',
                             help='path to file containing contract creation bytecode')

    sym_exec_arguments = parser.add_argument_group('symbolic execution arguments')
    sym_exec_arguments.add_argument('--timeout', metavar='SEC', type=float, default=DEFAULT_TIMEOUT,
                                    help='symbolic execution timeout, default: {} seconds'.format(DEFAULT_TIMEOUT))
    sym_exec_arguments.add_argument('--max-depth', type=int, default=DEFAULT_MAX_DEPTH,
                                    help='max graph depth, default: {}'.format(DEFAULT_MAX_DEPTH))

    networking_group = parser.add_argument_group('networking arguments')
    networking_group.add_argument('--rpc', metavar="RPC", type=Text, default=DEFAULT_RPC,
                                  help='JSON RPC provider URL, default: \'{}\''.format(DEFAULT_RPC))

    compilation_group = parser.add_argument_group('compilation arguments')
    compilation_group.add_argument('--solc', metavar='SOLC', type=Text, default=DEFAULT_SOLC,
                                   help='solc binary path, default: \'{}\''.format(DEFAULT_SOLC))

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
    report = symbolic_analysis.execute(contract_loader=contract_loader, timeout=args.timeout, max_depth=args.max_depth)
    print(report.to_json(pretty=True) if args.as_json else report.to_text())
