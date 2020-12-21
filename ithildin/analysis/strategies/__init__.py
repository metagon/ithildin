from enum import Enum

from .ownership import Ownership
from .x_confirmation import XConfirmation
from .off_chain_secret import OffChainSecret


class StrategyType(Enum):
    OWNERSHIP = 1
    X_CONFIRMATION = 2
    OFF_CHAIN_SECRET = 3


STRATEGY_MAP = {
    StrategyType.OWNERSHIP: Ownership,
    StrategyType.X_CONFIRMATION: XConfirmation,
    StrategyType.OFF_CHAIN_SECRET: OffChainSecret
}
