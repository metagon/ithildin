from typing import List

from .base import AnalysisStrategy
from .strategies.hash_lock import HashLock
from .strategies.ownership import Ownership
from .strategies.x_confirmation import XConfirmation

from ithildin.support.singleton import Singleton


class StrategyLoader(metaclass=Singleton):

    def __init__(self) -> None:
        self.strategies = []
        self._register_strategies()

    def get_strategies(self) -> List[AnalysisStrategy]:
        return self.strategies

    def register_strategy(self, strategy: AnalysisStrategy) -> None:
        assert strategy is not None, 'No strategy provided'
        self.strategies.append(strategy)

    def _register_strategies(self) -> None:
        self.strategies.extend([
            HashLock(),
            Ownership(),
            XConfirmation()
        ])
