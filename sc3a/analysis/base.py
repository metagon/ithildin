from abc import ABC, abstractmethod
from typing import Optional, List, Text

from mythril.ethereum.evmcontract import EVMContract


class AnalysisStrategy(ABC):

    @abstractmethod
    def execute(self, contract: EVMContract) -> Optional[List[Text]]:
        """Execute the analysis strategy.
        Parameters
        ----------
        contract: EVMContract
            EVM contract to be analyzed.
        """
        pass
