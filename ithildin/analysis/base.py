import logging
import re

from abc import ABC, abstractmethod
from typing import List, Optional, Set, Text

from ithildin.model.report import ReportItem, Result

from mythril.exceptions import UnsatError
from mythril.laser.ethereum.cfg import Constraints
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.support.model import get_model

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
    address_cache: Set[int] = set()
    results: List[ReportItem] = []

    def reset(self):
        self.address_cache = set()
        self.results = []

    def generate_report(self):
        report = ReportItem(self.report_title, self.report_description, self.pattern_name)
        for result in self.results:
            report.add_result(result)
        return report

    def execute(self, state: GlobalState) -> Optional[Result]:
        """ Execute analysis strategy on the given state. """
        if state.instruction['address'] in self.address_cache:
            return None
        log.debug('Executing analysis strategy %s', type(self).__name__)
        result = self._analyze(state)
        if result is not None:
            log.info('Analysis strategy %s got a hit in function %s', type(self).__name__, result.function_name)
            self.results.append(result)
            self.address_cache.add(state.instruction['address'])
        return result

    @abstractmethod
    def _analyze(self, state: GlobalState) -> Optional[Result]:
        """ Actual implementation of the analysis strategy. Override this when inheriting AnalysisStrategy. """
        pass

    def _is_unsat(self, proposition: Constraints) -> bool:
        """
        Checks if the *proposition* is unsatisfiable.

        Parameters
        ----------
        proposition: Constraints
            The proposition to check.

        Returns
        -------
        True if the proposition is unsat, False otherwise.
        """
        try:
            model = get_model(proposition)
            log.debug('Violation found...')
            log.debug('### BEGIN DECLARATIONS ###')
            for d in model.decls():
                log.debug("<DECL %s = %s>", d.name(), re.sub(r'\s{2,}', ' ', str(model[d]).replace('\n', ' ')))
            log.debug('### END DECLARATIONS ###')
            return False
        except UnsatError:
            return True
