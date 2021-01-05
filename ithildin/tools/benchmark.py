import csv
import hashlib
import logging
import math
import os
import random
import time

from functools import lru_cache
from typing import Optional, Set, Text

from ithildin.analysis.loader import StrategyLoader
from ithildin.analysis.symbolic import LaserWrapper
from ithildin.analysis.loader import Ownership, XConfirmation
from ithildin.contract.loader_factory import get_factory, LoaderFactoryType
from ithildin.report.benchmark import Report, Result
from ithildin.support.compiler_version import Version, VersionMatcher

log = logging.getLogger(__name__)

TIME_FORMAT = '%Y-%m-%d %H:%M:%S (%z)'
STRATEGIES = {
    'ownership': Ownership(),
    'x-confirmation': XConfirmation()
}


def start_verification(report: Report, verification_sample: Set[int]) -> None:
    print()
    print('=' * 80)
    print('! Entering verification mode...')
    for result in report.results:
        if result.contract_index not in verification_sample:
            continue
        print('! Verifying contract at address %s' % result.contract_address)
        print('! Results:\n' + result.to_json(pretty=True))
        # TODO: Does mythril contain any function for retrieving this value?
        print('! How many functions does the contract contain in total (excluding constructors)?')
        total_functions_count = int(input('> Your answer: '), base=10)
        if result.total_hits > 0:
            print('! Did the analysis strategy correctly identify *all* functions in the contract?')
            answer = input('> Your answer [y/n]: ')
            while answer not in {'y', 'n'}:
                answer = input('> Enter a valid answer [y/n]: ')
            if answer == 'y':
                result.true_positives = result.total_hits
                result.true_negatives = total_functions_count - result.total_hits
            else:
                false_positive_count = int(input('> How many FALSE POSITIVES: '), base=10)
                false_negative_count = int(input('> How many FALSE NEGATIVES: '), base=10)
                result.true_positives = result.total_hits - false_positive_count
                result.false_positives = false_positive_count
                result.true_negatives = total_functions_count - false_negative_count - result.total_hits
                result.false_negatives = false_negative_count
        else:
            print('! The analysis strategy reported no results for this contract, is that correct?')
            answer = input('> Your answer [y/n]: ')
            while answer not in {'y', 'n'}:
                answer = input('> Enter a valid answer [y/n]: ')
            if answer == 'y':
                result.true_negatives = total_functions_count
            else:
                false_negative_count = int(input('> How many FALSE NEGATIVES: '), base=10)
                result.true_negatives = total_functions_count - false_negative_count
                result.false_negatives = false_negative_count
        result.verified = True
    print('=' * 80)
    print(report.to_markdown())


@lru_cache(maxsize=5)
def count_rows(file: Text, delimiter=',') -> int:
    with open(file, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=delimiter)
        return sum(1 for _ in csv_reader)


def generate_contract_sample(file: Text,
                             sample_size: int,
                             address_column: int,
                             compiler_name_column: Optional[int] = None,
                             compiler_version_column: Optional[int] = None,
                             has_header: Optional[bool] = True,
                             delimiter: Optional[Text] = ',',
                             version_matcher: Optional[VersionMatcher] = None) -> Set[int]:
    if version_matcher is not None:
        assert compiler_version_column is not None, 'Compiler version column not provided'
        matched_version_indexes = set()
        with open(file, 'r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=delimiter)
            for i, row in enumerate(csv_reader):
                if compiler_name_column is None or row[compiler_name_column].startswith('Solidity'):
                    try:
                        version = Version(raw=row[compiler_version_column])
                    except ValueError:
                        continue
                    if version_matcher.matches(version):
                        matched_version_indexes.add(i)
        return set(random.sample(matched_version_indexes, sample_size))
    else:
        row_count = count_rows(file, delimiter=delimiter)
        return set(random.sample(range(1 if has_header else 0, row_count), sample_size))


def benchmark(args) -> None:
    random.seed(args.random_seed)
    instance_count = count_rows(args.filename, delimiter=args.csv_delimiter) - 1 if args.has_header else 0
    file_sha256sum = hashlib.sha256(open(args.filename, 'rb').read()).hexdigest()
    contract_sample = generate_contract_sample(args.filename, args.sample_size, args.address_column,
                                               compiler_name_column=args.compiler_column, compiler_version_column=args.version_column,
                                               has_header=args.has_header, delimiter=args.csv_delimiter, version_matcher=args.compiler_target)
    benchmark_report = Report(args.strategy.capitalize(), args.random_seed, args.timeout, args.max_depth, args.verification_ratio,
                              contracts_filename=os.path.basename(args.filename), file_sha256sum=file_sha256sum,
                              start_time=time.strftime(TIME_FORMAT), target_version=args.compiler_target.raw if args.compiler_target else None)
    rpc = 'https://mainnet.infura.io/v3/' + args.infura_project_id
    strategy_loader = StrategyLoader()
    strategy_loader.set_strategies([STRATEGIES[args.strategy]])
    positive_instances = set()
    with open(args.filename, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=args.csv_delimiter)
        for i, row in enumerate(csv_reader):
            if i not in contract_sample:
                continue
            target_address = row[args.address_column]
            log.info('Analyzing contract %d/%d at address %s', i + 1, instance_count, target_address)
            loader_factory = get_factory(LoaderFactoryType.JSON_RPC, address=target_address, rpc=rpc)
            analysis_report = LaserWrapper().execute(contract_loader=loader_factory.create(), timeout=args.timeout, max_depth=args.max_depth)
            if sum(len(report_item.results) for report_item in analysis_report.reports) > 0:
                positive_instances.add(i)
            else:
                log.info('Nothing found for contract %d/%d at address %s', i + 1, instance_count, target_address)
            function_names = [result.function_name
                              for report_item in analysis_report.reports if len(report_item.results) > 0
                              for result in report_item.results]
            compiler_version = row[args.version_column] if args.version_column is not None else None
            benchmark_report.add_result(Result(target_address, i, function_names, compiler_version=compiler_version))
            strategy_loader.reset_strategies()
    benchmark_report.end_time = time.strftime(TIME_FORMAT)
    negative_instances = contract_sample - positive_instances
    positive_sample = set(random.sample(positive_instances, math.ceil(len(positive_instances) * args.verification_ratio)))
    negative_sample = set(random.sample(negative_instances, math.ceil(len(negative_instances) * args.verification_ratio)))
    start_verification(benchmark_report, positive_sample | negative_sample)
