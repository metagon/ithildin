import logging

from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.analysis import Result

log = logging.getLogger(__name__)


class CallData:
    """ Annotation for input data. """
    pass


class HashedInput:
    """ Annotation to be used on SHA3 elements. """
    pass


class HashedStorage:
    """ Annotation to be used on SLOAD elements, where the lookup key has been hashed. """
    pass


class HashLock(AnalysisStrategy):

    pattern_name = 'HASH_LOCK'
    report_title = 'Hash Lock (Off-Chain Secret Enabled Authentication)'
    report_description = ('This pattern aims at providing authentication when the account is not known in advance. '
                          'A secret is fixed off-chain and hashed, and the hash gets submitted to the contract. '
                          'Later, the holder of the secret can submit it to the contract, the contract checks '
                          'the secret\'s hash against the stored one, and if they match the protected logic gets executed.')

    pre_hooks = ['JUMPI', 'SLOAD']
    post_hooks = ['SHA3', 'SLOAD', 'CALLDATALOAD']

    def __init__(self):
        super().__init__()
        self.hashed_sload_cache = set()

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state and prev_state.instruction['opcode'] == 'CALLDATALOAD':
            state.mstate.stack[-1].annotate(CallData())
        elif prev_state and prev_state.instruction['opcode'] == 'SHA3' and self._has_annotation(state.mstate.stack[-1], CallData):
            state.mstate.stack[-1].annotate(HashedInput())
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD' and prev_state.instruction['address'] in self.hashed_sload_cache:
            self.hashed_sload_cache.remove(prev_state.instruction['address'])
            state.mstate.stack[-1].annotate(HashedStorage())

        if state.instruction['opcode'] == 'SLOAD' and self._has_annotation(state.mstate.stack[-1], HashedInput):
            # Workaround since annotations don't get propagated on loaded stack element.
            # Annotation gets added on SLOAD post_hook (see condition above).
            self.hashed_sload_cache.add(state.instruction['address'])
        elif state.instruction['opcode'] == 'JUMPI' and self._has_annotation(state.mstate.stack[-2], HashedStorage):
            return Result(state.environment.active_function_name)

        return None
