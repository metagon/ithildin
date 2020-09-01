from abc import ABC, abstractmethod
from typing import Optional, List, Text

from mythril.ethereum.evmcontract import EVMContract

class AnalysisStrategy(ABC):
    def __init__(self, contract: EVMContract):
        """Initialize an analysis strategy.
        Parameters
        ----------
        contract: EVMContract
            EVM contract to be analyzed.
        """
        self.contract = contract

    @abstractmethod
    def execute(self) -> Optional[List[Text]]:
        """Execute the analysis strategy.
        """
        pass
