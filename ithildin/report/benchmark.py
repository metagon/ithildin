import json

from jinja2 import Environment, PackageLoader
from typing import List, Optional, Text


class Result:

    def __init__(self, contract_address: Text, contract_index: int, detected_functions: List[Text]) -> None:
        self.contract_address = contract_address
        self.contract_index = contract_index
        self.detected_functions = detected_functions
        self.verified = False
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0

    @property
    def total_hits(self) -> int:
        return len(self.detected_functions)

    @property
    def total_functions_count(self):
        return self.true_positives + self.false_positives + self.true_negatives + self.false_negatives

    def to_dict(self):
        return {
            'contractAddress': self.contract_address,
            'contractIndex': self.contract_index,
            'detectedFunctions': self.detected_functions
        }

    def to_json(self, pretty=False):
        return json.dumps(self.to_dict(), indent=2 if pretty else None)


class Report:

    def __init__(self, strategy_name: Text, random_seed: int, exec_timeout: int, max_depth: int,
                 verification_ratio: float, contracts_filename=None, file_sha256sum=None, start_time=None, end_time=None) -> None:
        self.strategy_name = strategy_name
        self.random_seed = random_seed
        self.exec_timeout = exec_timeout
        self.max_depth = max_depth
        self.verification_ratio = verification_ratio
        self.contracts_filename = contracts_filename
        self.file_sha256sum = file_sha256sum
        self.start_time = start_time
        self.end_time = end_time
        self._results: List[Result] = []

    @property
    def results(self) -> List[Result]:
        return self._results

    def add_result(self, result: Result) -> None:
        assert result is not None
        self._results.append(result)

    @property
    def sample_size(self) -> int:
        return len(self.results)

    @property
    def total_detections(self) -> int:
        return sum(result.total_hits for result in self.results)

    @property
    def true_positives(self) -> int:
        return sum(result.true_positives for result in self.results if result.verified)

    @property
    def false_positives(self) -> int:
        return sum(result.false_positives for result in self.results if result.verified)

    @property
    def true_negatives(self) -> int:
        return sum(result.true_negatives for result in self.results if result.verified)

    @property
    def false_negatives(self) -> int:
        return sum(result.false_negatives for result in self.results if result.verified)

    @property
    def precision(self) -> Optional[float]:
        try:
            return self.true_positives / (self.true_positives + self.false_positives)
        except ZeroDivisionError:
            return None

    @property
    def recall(self) -> Optional[float]:
        try:
            return self.true_positives / (self.true_positives + self.false_negatives)
        except ZeroDivisionError:
            return None

    def to_markdown(self):
        environment = Environment(loader=PackageLoader('ithildin.report'), trim_blocks=True)
        template = environment.get_template('benchmark_report.md.jinja2')
        return template.render(report=self)

    def __repr__(self) -> Text:
        return (
            '<Report '
            'strategy_name={0.strategy_name} '
            'random_seed={0.random_seed} '
            'exec_timeout={0.exec_timeout} '
            'verification_ratio={0.verification_ratio} '
            'contracts_filename={0.contracts_filename} '
            'start_time={0.start_time} '
            'end_time={0.end_time} '
            'results={0.results}'
            '>'
        ).format(self)
