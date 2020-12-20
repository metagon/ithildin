from typing import Union

from .base import AnalysisStrategy
from .strategies import STRATEGY_MAP, StrategyType
from ithildin.loader.contract_loader import FileLoader, Web3Loader


class AnalysisStrategyFactory:

    def __init__(self, contract_loader: Union[FileLoader, Web3Loader]) -> None:
        self.contract_loader = contract_loader

    def create(self, strategy_type: StrategyType) -> AnalysisStrategy:
        if strategy_type not in StrategyType:
            raise AttributeError('Strategy \'%s\' is not valid', strategy_type)
        # Get strategy instance based on type of ContractLoader
        if isinstance(self.contract_loader, FileLoader):
            contract = self.contract_loader.contract()
            return STRATEGY_MAP[strategy_type](creation_code=contract.creation_disassembly.bytecode)
        elif isinstance(self.contract_loader, Web3Loader):
            return STRATEGY_MAP[strategy_type](target_address=self.contract_loader.address, dyn_loader=self.contract_loader.dyn_loader)
        else:
            return None
