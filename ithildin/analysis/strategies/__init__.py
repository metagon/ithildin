from enum import Enum

from .ownership import Ownership
from .x_confirmation import XConfirmation


class StrategyType(Enum):
    OWNERSHIP = 1
    X_CONFIRMATION = 2

STRATEGY_MAP = {
    StrategyType.OWNERSHIP: Ownership,
    StrategyType.X_CONFIRMATION: XConfirmation
}
