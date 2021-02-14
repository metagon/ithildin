from typing import List

from .base import AnalysisStrategy
from .strategies.hash_lock import HashLock
from .strategies.multiple_authorization import MultipleAuthorization
from .strategies.ownership import Ownership
from .strategies.roles import RoleBasedAccessControl
from .strategies.x_confirmation import XConfirmation

from ithildin.support.singleton import Singleton

STRATEGIES = {
    HashLock.pattern_name: HashLock,
    MultipleAuthorization.pattern_name: MultipleAuthorization,
    Ownership.pattern_name: Ownership,
    RoleBasedAccessControl.pattern_name: RoleBasedAccessControl,
    XConfirmation.pattern_name: XConfirmation
}


class StrategyLoader(metaclass=Singleton):

    def __init__(self) -> None:
        self.strategies = []
        self.strategies.extend(self.default_strategies())

    def get_strategies(self) -> List[AnalysisStrategy]:
        return self.strategies

    def set_strategies(self, strategies: List[AnalysisStrategy]) -> None:
        assert strategies is not None and len(strategies) > 0
        self.strategies = strategies

    def register_strategy(self, strategy: AnalysisStrategy) -> None:
        assert strategy is not None, 'No strategy provided'
        self.strategies.append(strategy)

    def reset_strategies(self) -> None:
        for strategy in self.strategies:
            strategy.reset()

    def default_strategies(self) -> List[AnalysisStrategy]:
        return [Strategy() for Strategy in STRATEGIES.values()]
