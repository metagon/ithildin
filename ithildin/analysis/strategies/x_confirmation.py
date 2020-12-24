import logging
from typing import Optional

from mythril.laser.ethereum.state.global_state import GlobalState

from ithildin.analysis.base import AnalysisStrategy
from ithildin.model.report import Result

log = logging.getLogger(__name__)

PATTERN_NAME = 'X_CONFIRMATION'
REPORT_TITLE = 'X-Confirmation (Block Count)'
REPORT_DESCRIPTION = ('This pattern protects functions from being executed unless a condition related to the '
                      'current block number is met. For example one might want to wait for a certain number '
                      'of blocks to have passed before a transaction is marked as valid or confirmed.')


class XConfirmation(AnalysisStrategy):

    OPCODE_FLAGS = {
        'NUMBER': 0b001,
        'SLOAD':  0b010,
        'EQ':     0b100,
        'LT':     0b100,
        'GT':     0b100
    }

    OPCODE_FLAG_TARGET = 0b111

    def _analyze(self, state: GlobalState) -> Optional[Result]:
        return None
