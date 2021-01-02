import logging

from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.model import Result

log = logging.getLogger(__name__)


class CallData:
    """ Annotation for input data. """

    def __eq__(self, other):
        return isinstance(other, CallData)

    def __hash__(self):
        return hash(type(self))


class HashedInput:
    """ Annotation to be used on SHA3 elements. """

    def __init__(self, address: int):
        self.address = address

    def __eq__(self, other: 'HashedInput'):
        return self.address == other.address

    def __hash__(self):
        return hash((type(self), self.address))


class HashedStorage:

    def __eq__(self, other):
        return isinstance(other, HashedStorage)

    def __hash__(self):
        return hash(type(self))


class HashLock(AnalysisStrategy):

    pattern_name = 'HASH_LOCK'
    report_title = 'Hash Lock (Off-Chain Secret Enabled Authentication)'
    report_description = ('This pattern aims at providing authentication when the account is not known in advance. '
                          'A secret is fixed off-chain and hashed, and the hash gets submitted to the contract. '
                          'Later, the holder of the secret can submit it to the contract, the contract checks '
                          'the secret\'s hash against the stored one, and if they match the protected logic gets executed.')

    pre_hooks = ['JUMPI']
    post_hooks = ['SHA3', 'SLOAD', 'CALLDATALOAD']

    def __init__(self):
        super().__init__()

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state and prev_state.instruction['opcode'] == 'CALLDATALOAD':
            state.mstate.stack[-1].annotate(CallData())
        elif prev_state and prev_state.instruction['opcode'] == 'SHA3' and CallData() in state.mstate.stack[-1].annotations:
            state.mstate.stack[-1].annotate(HashedInput(prev_state.instruction['address']))
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD':
            for annotation in prev_state.mstate.stack[-1].annotations:
                prev_pc = prev_state.instruction['address']
                if isinstance(annotation, HashedInput) and annotation.address not in range(prev_pc - 4, prev_pc - 1):
                    state.mstate.stack[-1].annotate(HashedStorage())


        if state.instruction['opcode'] == 'JUMPI' and (
            HashedStorage() in state.mstate.stack[-2].annotations or
            self._has_annotation(state.mstate.stack[-2], HashedInput)
        ):
            return Result(state.environment.active_function_name)

        return None
