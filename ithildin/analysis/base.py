import logging

from abc import ABC, abstractmethod
from typing import List, Optional, Set, Text, Type

from ithildin.report.analysis import ReportItem, Result

from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt.bitvec import BitVec

log = logging.getLogger(__name__)


class AnalysisStrategy(ABC):
    """
    Base class for contract analysis strategies. Subclasses can be instantiated by using the AnalysisStrategyFactory
    from the module \'ithildin.analysis.factory\'.

    When creating a new analysis strategy by subclassing this base class, override the *_analyze()* function.
    """

    pattern_name = ''
    report_title = ''
    report_description = ''

    pre_hooks: List[Text] = []
    post_hooks: List[Text] = []

    def __init__(self):
        self.cache: Set[Text] = set()
        self.results: List[ReportItem] = []

    def reset(self) -> None:
        self.cache = set()
        self.results = []

    def generate_report(self) -> ReportItem:
        report = ReportItem(self.report_title, self.report_description, self.pattern_name)
        for result in self.results:
            report.add_result(result)
        return report

    def execute(self, state: GlobalState) -> Optional[Result]:
        """ Execute analysis strategy on the given state. """
        if state.environment.active_function_name in self.cache:
            return None
        log.debug('Executing analysis strategy %s', type(self).__name__)
        result = self._analyze(state, state.node.states[-1] if len(state.node.states) > 0 and state is not state.node.states[-1] else None)
        if result is not None:
            log.info('Analysis strategy %s got a hit in function %s', type(self).__name__, result.function_name)
            self.results.append(result)
            self.cache.add(state.environment.active_function_name)
        return result

    @abstractmethod
    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        """ Actual implementation of the analysis strategy. Override this when inheriting AnalysisStrategy. """
        pass

    def _has_annotation(self, bitvec: BitVec, annotation_type: Type) -> bool:
        """ Returns true if *bitvec* contains an annotation of type *annotation_type* """
        for annotation in bitvec.annotations:
            if isinstance(annotation, annotation_type):
                return True
        return False
