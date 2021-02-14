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


class HashedInputEq:
    """ Annotation to be used whenever the hashed input is involved in an equality operation. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other):
        return isinstance(other, HashedInputEq)


class Storage:
    """ Annotation to be used whenever something gets loaded from storage. """

    def __init__(self, index):
        self.index = index

    def __hash__(self):
        return hash((type(self), self.index))

    def __eq__(self, other):
        return self.index == other.index


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
    post_hooks = ['CALLDATALOAD', 'SHA3', 'SLOAD', 'EQ']

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
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD':
            # If the index is concrete, annotate the secret hash with the Storage taint, together with its index.
            if prev_state.mstate.stack[-1].symbolic is False:
                state.mstate.stack[-1].annotate(Storage(prev_state.mstate.stack[-1].value))
            # Annotate the value with the HashedStorage taint if the lookup key has been tainted with HashedInput.
            if HashedInput() in prev_state.mstate.stack[-1].annotations:
                state.mstate.stack[-1].annotate(HashedStorage())
        elif prev_state and prev_state.instruction['opcode'] == 'EQ' and \
                HashedInput() in state.mstate.stack[-1].annotations:
            # We add a distinct annotation whenever the hashed input is compared to something through equality.
            # This allows the analysis strategy to detect instances of the HashLock pattern when the secret hash
            # is not stored in a datastructure like a mapping.
            state.mstate.stack[-1].annotate(HashedInputEq())

        if state.instruction['opcode'] == 'JUMPI' and {HashedStorage(), HashedInputEq()} & state.mstate.stack[-2].annotations:
            result = Result(state.environment.active_function_name)
            if self._has_annotation(state.mstate.stack[-2], Storage):
                index = self._retrieve_storage_index(state.mstate.stack[-2])
                result.add_attribute('_index_secret_hash', index)
            return result

        return None

    def _retrieve_storage_index(self, bitvec) -> Optional[int]:
        for taint in bitvec.annotations:
            if isinstance(taint, Storage):
                return taint.index
        return None
