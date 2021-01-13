import logging

from argparse import ArgumentParser
from typing import Text

from ithildin import __version__
from ithildin.analysis.loader import STRATEGIES
from ithildin.analysis.symbolic import LaserWrapper
from ithildin.contract.loader_factory import get_factory, LoaderFactoryType
from ithildin.support.compiler_version import VersionParseAction
from ithildin.tools import benchmark_state_path
from ithildin.tools.benchmark import benchmark

# Default analysis arguments
DEFAULT_MAX_DEPTH = 128
DEFAULT_RPC = 'http://127.0.0.1:8545'
DEFAULT_SOLC = 'solc'
DEFAULT_TIMEOUT_ANALYSIS = 60

# Default benchmark arguments
DEFAULT_DELIMITER = ','
DEFAULT_HAS_HEADER = True
DEFAULT_ADDRESS_COLUMN = 0
DEFAULT_SAMPLE_SIZE = 5
DEFAULT_TIMEOUT_BENCHMARK = 90
DEFAULT_SEED = 1
DEFAULT_VERIFICATION_RATIO = 0.1


def populate_analysis_parser(parser: ArgumentParser) -> None:
    parser.add_argument('--json', action='store_true', dest='as_json', help='print report as JSON to standard output')

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-a', '--address', metavar='ADDRESS', type=Text, help='contract address to analyze')
    input_group.add_argument('-s', '--sol', metavar='PATH', type=Text, dest='sol_path', help='path to solidity contract')
    input_group.add_argument('-b', '--bin', metavar='PATH', type=Text, dest='bin_path',
                             help='path to file containing contract creation bytecode')

    sym_exec_arguments = parser.add_argument_group('symbolic execution arguments')
    sym_exec_arguments.add_argument('--timeout', metavar='SEC', type=int, default=DEFAULT_TIMEOUT_ANALYSIS,
                                    help='symbolic execution timeout (default: {})'.format(DEFAULT_TIMEOUT_ANALYSIS))
    sym_exec_arguments.add_argument('--max-depth', metavar='DEPTH', type=int, default=DEFAULT_MAX_DEPTH,
                                    help='max graph depth (default: {})'.format(DEFAULT_MAX_DEPTH))

    networking_group = parser.add_argument_group('networking arguments')
    networking_group.add_argument('--rpc', metavar="RPC", type=Text, default=DEFAULT_RPC,
                                  help='JSON RPC provider URL (default: \'{}\')'.format(DEFAULT_RPC))

    compilation_group = parser.add_argument_group('compilation arguments')
    compilation_group.add_argument('--solc', metavar='SOLC', type=Text, default=DEFAULT_SOLC,
                                   help='solc binary path (default: \'{}\')'.format(DEFAULT_SOLC))


def populate_benchmark_parser(parser: ArgumentParser) -> None:
    benchmark_subparsers = parser.add_subparsers(dest='benchmark_command', help='Commands')

    new_benchmark_parser = benchmark_subparsers.add_parser('new', help='start a new benchmark')
    new_benchmark_parser.add_argument('filename', metavar='FILE', type=str, help='the csv file containing contract instances')
    strategies_options = [strategy.replace('_', '-').lower() for strategy in STRATEGIES.keys()]
    new_benchmark_parser.add_argument('--strategy', choices=strategies_options, required=True, help='the strategy to benchmark')
    new_benchmark_parser.add_argument('--interactive', action='store_true', help='after analysis proceed to interactive verification mode')
    new_benchmark_parser.add_argument('--infura-project', dest='infura_project_id', metavar='PROJECT_ID', type=str, required=True,
                                      help='the Infura project ID for retrieving contract data from the mainchain')
    new_benchmark_parser.add_argument('--timeout', metavar='SEC', type=int, default=DEFAULT_TIMEOUT_BENCHMARK,
                                      help='the execution timeout for each contract (default: {})'.format(DEFAULT_TIMEOUT_BENCHMARK))
    new_benchmark_parser.add_argument('--max-depth', metavar='DEPTH', type=int, default=DEFAULT_MAX_DEPTH,
                                      help='max graph depth (default: {})'.format(DEFAULT_MAX_DEPTH))

    sampling_group = new_benchmark_parser.add_argument_group('sampling options')
    sampling_group.add_argument('--sample-size', metavar='SIZE', type=int, default=DEFAULT_SAMPLE_SIZE,
                                help='the sample size to be picked from the CSV instances (default: {})'.format(DEFAULT_SAMPLE_SIZE))
    sampling_group.add_argument('--random-seed', metavar='SEED', type=int, default=DEFAULT_SEED,
                                help='a seed for the sampling RNG (default: {})'.format(DEFAULT_SEED))
    sampling_group.add_argument('--verification-ratio', metavar='RATIO', type=float, default=DEFAULT_VERIFICATION_RATIO,
                                help='the ratio of the sampled contracts to manually verify (default: {})'.format(DEFAULT_VERIFICATION_RATIO))
    sampling_group.add_argument('--compiler-target', metavar='x.x.x', action=VersionParseAction,
                                help='the Solidity compiler target to match in the sample (e.g. ^0.7.0)')

    csv_group = new_benchmark_parser.add_argument_group('CSV arguments')
    csv_group.add_argument('--has-header', action='store_true', default=DEFAULT_HAS_HEADER,
                           help='does the CSV file contain a header (default: {})'.format(DEFAULT_HAS_HEADER))
    csv_group.add_argument('--csv-delimiter', metavar='DELIMITER', type=str, default=DEFAULT_DELIMITER,
                           help='the CSV delimiter (default: \'{}\')'.format(DEFAULT_DELIMITER))
    csv_group.add_argument('--address-column', metavar='COL', type=int, default=DEFAULT_ADDRESS_COLUMN,
                           help='column index that contains the contract addresses (default: {})'.format(DEFAULT_ADDRESS_COLUMN))
    csv_group.add_argument('--compiler-column', metavar='COL', type=int, help='the column containing the compiler name')
    csv_group.add_argument('--version-column', metavar='COL', type=int,
                           help='column index that contains the compiler version used')

    verify_benchmark_parser = benchmark_subparsers.add_parser('verify', help='verify previously stored benchmark state in interactive mode')
    verify_benchmark_parser.add_argument('--file', metavar='FILE', dest='benchmark_state_file', default=benchmark_state_path,
                                         help='path to benchmark state file (default: {})'.format(benchmark_state_path))


def get_parser() -> ArgumentParser:
    program_name = 'Ithildin - EVM bytecode semantic analysis tool based on Mythril'
    parser = ArgumentParser(description=program_name)
    parser.add_argument('--version', action='version', version='Ithildin v{}'.format(__version__))
    parser.add_argument('--verbose', action='store_true', help='print debugging output')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    # Add analysis parser
    analysis_parser = subparsers.add_parser('analyze', help='begin analysis of a contract')
    populate_analysis_parser(analysis_parser)
    # Add benchmark parser
    benchmark_parser = subparsers.add_parser('benchmark', help='execute benchmarking tool')
    populate_benchmark_parser(benchmark_parser)

    return parser


def analyze(args) -> None:
    # Get the contract loader factory based on the specified options
    if args.bin_path:
        contract_loader_factory = get_factory(LoaderFactoryType.BINARY, path=args.bin_path)
    elif args.sol_path:
        contract_loader_factory = get_factory(LoaderFactoryType.SOLIDITY, path=args.sol_path, solc=args.solc)
    elif args.address:
        contract_loader_factory = get_factory(LoaderFactoryType.JSON_RPC, address=args.address, rpc=args.rpc)
    else:
        raise NotImplementedError('This feature hasn\'t been implemented yet')

    contract_loader = contract_loader_factory.create()
    symbolic_analysis = LaserWrapper()
    report = symbolic_analysis.execute(contract_loader=contract_loader, timeout=args.timeout, max_depth=args.max_depth)
    print(report.to_json(pretty=True) if args.as_json else report.to_text())


def main():
    parser = get_parser()
    args = parser.parse_args()
    # Set logging level to DEBUG for all logers if the *--verbose* option was specified
    if args.verbose:
        for logger in [logging.getLogger(name) for name in logging.root.manager.loggerDict]:
            if args.verbose:
                logger.setLevel(logging.DEBUG)

    if args.command == 'analyze':
        analyze(args)
    elif args.command == 'benchmark' and args.benchmark_command is not None:
        benchmark(args)
    else:
        parser.print_help()
        exit(1)
