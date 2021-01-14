import csv
import json
import hashlib
import logging
import os
import random
import time

from functools import lru_cache
from typing import Optional, Set, Text, Tuple

from mythril.support.signatures import SignatureDB
from mythril.mythril import MythrilDisassembler

from . import benchmark_state_path
from .verification_db.verification_db import Contract, Flag
from .verification_db.contract_repository import ContractRepository
from .verification_db.function_repository import FunctionRepository
from .verification_db.flagged_function_repository import FlaggedFunctionRepository
from ithildin.analysis.loader import StrategyLoader
from ithildin.analysis.symbolic import LaserWrapper
from ithildin.analysis.loader import STRATEGIES
from ithildin.contract.loader_factory import get_factory, LoaderFactoryType
from ithildin.report.benchmark import Report, Result
from ithildin.support.compiler_version import Version, VersionMatcher

TIME_FORMAT = '%Y-%m-%d %H:%M:%S (%z)'

log = logging.getLogger(__name__)
contract_repository = ContractRepository()
function_repository = FunctionRepository()
flagged_function_repository = FlaggedFunctionRepository()
signature_db = SignatureDB(enable_online_lookup=True)


@lru_cache(maxsize=1)
def count_rows(file: Text, delimiter=',') -> int:
    with open(file, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=delimiter)
        return sum(1 for _ in csv_reader)


@lru_cache(maxsize=2048)
def signature_hash(signature: Text) -> Text:
    if signature.startswith('_function'):
        return signature[-10:]
    else:
        return MythrilDisassembler.hash_for_function_signature(signature)


@lru_cache(maxsize=2048)
def lookup_signature(signature_hash: Text) -> Text:
    func_signatures = signature_db[signature_hash]
    return func_signatures[0] if len(func_signatures) > 0 else f'_function_{signature_hash}'


def save_benchmark_state(report: Report, positive_sample: Set[int], negative_sample: Set[int]) -> None:
    log.info('Saving benchmark state to filesystem...')
    benchmark_state = {
        'report': report.to_dict(),
        'positiveSample': list(positive_sample),
        'negativeSample': list(negative_sample)
    }
    with open(benchmark_state_path, 'w', encoding='utf-8') as file:
        json.dump(benchmark_state, file, ensure_ascii=False)
        log.info('Saved benchmark state to file: %s', benchmark_state_path)


def load_benchmark_state(path=benchmark_state_path) -> Tuple[Report, Set[int], Set[int]]:
    log.info('Loading benchmark state from file: %s', path)
    with open(path, 'r', encoding='utf-8') as file:
        benchmark_state = json.load(file)
        positive_sample = set(benchmark_state['positiveSample'])
        negative_sample = set(benchmark_state['negativeSample'])
        report = Report(benchmark_state['report']['strategyName'],
                        benchmark_state['report']['randomSeed'],
                        benchmark_state['report']['execTimeout'],
                        benchmark_state['report']['maxDepth'],
                        benchmark_state['report']['verificationRatio'],
                        target_version=benchmark_state['report'].get('targetVersion', None),
                        contracts_filename=benchmark_state['report'].get('contractsFilename', None),
                        file_sha256sum=benchmark_state['report'].get('fileSha256Sum', None),
                        start_time=benchmark_state['report'].get('startTime', None),
                        end_time=benchmark_state['report'].get('endTime', None))
        for result in benchmark_state['report']['results']:
            if len(result['functionHashes']) == 0:
                continue
            report.add_result(Result(result['functionHashes'],
                                     result['contractAddress'],
                                     result['contractIndex'],
                                     result['detectedFunctions'],
                                     result['compilerVersion']))
        return report, positive_sample, negative_sample


def get_binary_answer() -> bool:
    answer = input('> Your answer [y/n]: ')
    while answer not in {'y', 'n'}:
        answer = input('> Enter a valid answer [y/n]: ')
    return answer == 'y'


def check_for_existing_flags(result: Result, contract: Contract, strategy: Text, all_func_hashes: Set[Text], marked_func_hashes: Set[Text]):
    existing_hashes = set()
    for func_hash in all_func_hashes:
        func_entity = function_repository.get(contract, signature_hash=func_hash)
        if func_entity is None:
            continue
        flagged_funcion = flagged_function_repository.get(func_entity, strategy)
        if flagged_funcion is None:
            continue
        if flagged_funcion.flag == Flag.VALID:
            if func_hash in marked_func_hashes:
                result.true_positives += 1
            else:
                result.false_negatives += 1
            existing_hashes.add(func_hash)
        elif flagged_funcion.flag == Flag.INVALID:
            if func_hash in marked_func_hashes:
                result.false_positives += 1
            else:
                result.true_negatives += 1
            existing_hashes.add(func_hash)
        if flagged_funcion.flag is not None:
            print('! Found existing flag for signature {0.flag}: {0.function.signature}'.format(flagged_funcion))
    return existing_hashes


def ask_for_marked_functions(result: Result, contract: Contract, strategy: Text, existing_hashes: Set[Text]):
    for signature, sig_hash in [(sig, signature_hash(sig)) for sig in result.detected_functions if signature_hash(sig) not in existing_hashes]:
        print('! Has the function "{}" been correctly identified?'.format(signature))
        answer = get_binary_answer()
        if answer:
            result.true_positives += 1
        else:
            result.false_positives += 1
        func_entity = function_repository.save(contract, signature, sig_hash)
        flagged_function_repository.set_flag(func_entity, strategy, Flag.VALID if answer else Flag.INVALID)


def ask_for_missing_functions(result: Result, contract: Contract, strategy: Text, valid_func_hashes: Set[Text]) -> Set[Text]:
    if len(valid_func_hashes) == 0:
        return set()
    missing_functions = set()
    print('! One by one, enter all function signatures that were missed by the strategy (type \'c\' if none are left)')
    signature = input('> Signature (type \'c\' to continue): ')
    while signature != 'c':
        sig_hash = signature_hash(signature)
        if sig_hash in valid_func_hashes:
            missing_functions.add(signature)
        else:
            print('! "{}" is not an accepted signature'.format(signature))
        signature = input('> Signature (type \'c\' to continue): ')
    # Mark missing functions as valid in DB and increment false negative count
    for signature in missing_functions:
        func_entity = function_repository.save(contract, signature, signature_hash(signature))
        flagged_function_repository.set_flag(func_entity, strategy, Flag.VALID)
        result.false_negatives += 1
    return missing_functions


def start_verification(report: Report, verification_sample: Set[int]) -> None:
    print('\n' + '=' * 80)
    print('! Entering verification mode...')
    strategy = report.strategy_name.replace('-', '_').upper()
    for result in report.results:
        if result.contract_index not in verification_sample:
            continue
        contract = contract_repository.save(result.contract_address, result.compiler_version)
        func_hashes = set(result.function_hashes)
        marked_hashes = {signature_hash(sig) for sig in result.detected_functions}
        print('! Verifying contract at address %s' % result.contract_address)
        print('! Total functions in contract: %d' % len(func_hashes))
        # Check for already existing flags in the database
        existing_hashes = check_for_existing_flags(result, contract, strategy, func_hashes, marked_hashes)
        # Ask user to verify all functions that have been marked by the strategy
        ask_for_marked_functions(result, contract, strategy, existing_hashes)
        # Check all functions that haven't been marked by the strategy
        # First, ask user for any missing functions and mark them as VALID
        missing_functions = ask_for_missing_functions(result, contract, strategy, func_hashes - existing_hashes - marked_hashes)
        missing_hashes = {signature_hash(signature) for signature in missing_functions}
        # Next, mark all remaining functions as INVALID
        for func_hash in func_hashes - marked_hashes - existing_hashes - missing_hashes:
            func_entity = function_repository.get(contract, signature_hash=func_hash)
            if func_entity is None:
                signature = lookup_signature(func_hash)
                func_entity = function_repository.save(contract, signature, func_hash)
            flagged_function_repository.set_flag(func_entity, strategy, Flag.INVALID)
            result.true_negatives += 1
        result.verified = True
    print('=' * 80)
    print(report.to_markdown())


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
        matched_version_indices = set()
        with open(file, 'r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=delimiter)
            for i, row in enumerate(csv_reader):
                if compiler_name_column is None or row[compiler_name_column].strip() == 'Solidity':
                    try:
                        version = Version(raw=row[compiler_version_column])
                    except ValueError:
                        continue
                    if version_matcher.matches(version):
                        matched_version_indices.add(i)
        return set(random.sample(matched_version_indices, sample_size))
    else:
        row_count = count_rows(file, delimiter=delimiter)
        return set(random.sample(range(1 if has_header else 0, row_count), sample_size))


def new_benchmark(args) -> None:
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
    strategy_name = args.strategy.replace('-', '_').upper()
    strategy_loader = StrategyLoader()
    strategy_loader.set_strategies([STRATEGIES[strategy_name]()])
    positive_instances = set()
    with open(args.filename, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=args.csv_delimiter)
        for i, row in enumerate(csv_reader):
            if i not in contract_sample:
                continue
            target_address = row[args.address_column]
            log.info('Analyzing contract %d/%d at address %s', i + 1, instance_count, target_address)
            loader_factory = get_factory(LoaderFactoryType.JSON_RPC, address=target_address, rpc=rpc)
            contract_loader = loader_factory.create()
            analysis_report = LaserWrapper().execute(contract_loader=contract_loader, timeout=args.timeout, max_depth=args.max_depth)
            if sum(len(report_item.results) for report_item in analysis_report.reports) > 0:
                positive_instances.add(i)
            else:
                log.info('Nothing found for contract %d/%d at address %s', i + 1, instance_count, target_address)
            detected_functions = [result.function_name
                                  for report_item in analysis_report.reports if len(report_item.results) > 0
                                  for result in report_item.results]
            compiler_version = row[args.version_column] if args.version_column is not None else None
            function_hashes = contract_loader.disassembly().func_hashes if contract_loader.disassembly() else []
            benchmark_report.add_result(Result(function_hashes, target_address, i, detected_functions, compiler_version=compiler_version))
            strategy_loader.reset_strategies()
    benchmark_report.end_time = time.strftime(TIME_FORMAT)
    negative_instances = contract_sample - positive_instances
    positive_sample = set(random.sample(positive_instances, round(len(positive_instances) * args.verification_ratio)))
    negative_sample = set(random.sample(negative_instances, round(len(negative_instances) * args.verification_ratio)))
    save_benchmark_state(benchmark_report, positive_sample, negative_sample)
    if args.interactive:
        start_verification(benchmark_report, positive_sample | negative_sample)
        os.remove(benchmark_state_path)


def verify_benchmark(benchmark_state_file: Text) -> None:
    report, positive_sample, negative_sample = load_benchmark_state(benchmark_state_file)
    start_verification(report, positive_sample | negative_sample)
    os.remove(benchmark_state_file)


def benchmark(args) -> None:
    if args.benchmark_command == 'new':
        if os.path.exists(benchmark_state_path):
            print('! A benchmark state from a previous session exists. Do you want to override it?')
            answer = get_binary_answer()
            if not answer:
                print('! Terminating. Run \'ithil benchmark verify\' to manually verify the old benchmark state.')
                return
        new_benchmark(args)
    elif args.benchmark_command == 'verify':
        verify_benchmark(args.benchmark_state_file)
