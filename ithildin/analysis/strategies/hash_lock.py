import logging

from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.analysis import Result


class Input:
    """ Annotation for input data. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other):
        return isinstance(other, Input)


class HashedInput:
    """ Annotation to be used on SHA3 elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other):
        return isinstance(other, HashedInput)


class HashedStorage:
    """ Annotation to be used on SLOAD elements, where the lookup key has been hashed. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other):
        return isinstance(other, HashedStorage)


class HashLock(AnalysisStrategy):

    pattern_name = 'HASH_LOCK'
    report_title = 'Hash Lock (Off-Chain Secret Enabled Authentication)'
    report_description = ('This pattern aims at providing authentication when the account is not known in advance. '
                          'A secret is fixed off-chain and hashed, and the hash gets submitted to the contract. '
                          'Later, the holder of the secret can submit it to the contract, the contract checks '
                          'the secret\'s hash against the stored one, and if they match the protected logic gets executed.')

    pre_hooks = ['JUMPI']
    post_hooks = ['CALLDATALOAD', 'SHA3', 'SLOAD']

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state and prev_state.instruction['opcode'] == 'CALLDATALOAD':
            state.mstate.stack[-1].annotate(Input())
        elif prev_state and prev_state.instruction['opcode'] == 'SHA3' and \
                Input() in state.mstate.stack[-1].annotations and \
                prev_state.mstate.stack[-2].value <= 0x20:
            # Additionally check if the length of the memory content that has been hashed is less than 32 bytes long.
            # This helps mitigate the false positives that result from computing the hashes for looking up storage values,
            # since the key will always be larger than 32 bytes.
            state.mstate.stack[-1].annotate(HashedInput())
            state.mstate.stack[-1].annotations.discard(Input())
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD' and \
                HashedInput() in prev_state.mstate.stack[-1].annotations:
            state.mstate.stack[-1].annotate(HashedStorage())

        if state.instruction['opcode'] == 'JUMPI' and HashedStorage() in state.mstate.stack[-2].annotations:
            return Result(state.environment.active_function_name)

        return None
