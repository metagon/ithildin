import logging

from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.model import Result

log = logging.getLogger(__name__)


PATTERN_NAME = 'HASH_LOCK'
REPORT_TITLE = 'Hash Lock (Off-Chain Secret Enabled Authentication)'
REPORT_DESCRIPTION = ('This pattern aims at providing authentication when the account is not known in advance. '
                      'A secret is fixed off-chain and hashed, and the hash gets submitted to the contract. '
                      'Later, the holder of the secret can submit it to the contract, the contract checks '
                      'the secret\'s hash against the stored one, and if they match the protected logic gets executed.')


class HashLock(AnalysisStrategy):

    ENCODE_PACKED_SEQUENCE = [
        {'opcode': 'PUSH1', 'argument': '0x20'},
        {'opcode': 'ADD'},
        {'opcode': 'SHA3'}
    ]

    def _analyze(self, state: GlobalState) -> Optional[Result]:
        return None
