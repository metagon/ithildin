from typing import List

from .base import AnalysisStrategy
from .strategies.ownership import Ownership


class StrategyLoader:

    def __init__(self) -> None:
        self.strategies = []
        self._register_strategies()

    def get_strategies(self) -> List[AnalysisStrategy]:
        return self.strategies

    def register_strategy(self, strategy: AnalysisStrategy) -> None:
        assert strategy is not None, 'No strategy provided'

    def _register_strategies(self) -> None:
        self.strategies.extend([
            Ownership()
        ])
