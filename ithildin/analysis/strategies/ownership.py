from typing import Optional

from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt.bitvec import BitVec

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.analysis import Result


class Caller:
    """ Class to be used as annotation for CALLER elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'Caller'):
        return isinstance(other, Caller)


class Storage:
    """ Class to be used as annotation for SLOAD elements. """

    def __init__(self, storage_address: Optional[int] = None):
        self.storage_address = storage_address

    def __hash__(self):
        return hash((type(self), self.storage_address))

    def __eq__(self, other: 'Storage'):
        return self.storage_address == other.storage_address


class Compared:
    """ Class to be used as annotation for the EQ result. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other: 'Compared'):
        return isinstance(other, Compared)


class Ownership(AnalysisStrategy):

    pattern_name = 'OWNERSHIP'
    report_title = 'Ownership'
    report_description = ('This pattern aims at restricting functions to specific addresses. For example '
                          'the owner of the contract is specified in the constructor and only that account '
                          'is allowed to access a function and change the contract\'s state.')

    pre_hooks = ['JUMPI']
    post_hooks = ['CALLER', 'SLOAD', 'EQ']

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state and prev_state.instruction['opcode'] == 'CALLER':
            state.mstate.stack[-1].annotate(Caller())
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD' and prev_state.mstate.stack[-1].symbolic is False:
            index = prev_state.mstate.stack[-1].value
            if index <= 0xFF:
                # Restrict memorizing storage keys that result from some sort of hashing
                # by checking if the index is less than 256.
                state.mstate.stack[-1].annotate(Storage(index))
        elif prev_state and prev_state.instruction['opcode'] == 'EQ' and \
                ((Caller() in prev_state.mstate.stack[-1].annotations and self._has_annotation(prev_state.mstate.stack[-2], Storage)) or
                 (Caller() in prev_state.mstate.stack[-2].annotations and self._has_annotation(prev_state.mstate.stack[-1], Storage))):
            # Check if both top stack elemnts have been annotated with Caller and Storage,
            # in which case we annotate the equality result with the Compared annotation.
            state.mstate.stack[-1].annotate(Compared())

        if state.instruction['opcode'] == 'JUMPI' and Compared() in state.mstate.stack[-2].annotations:
            storage_address = self._retrieve_storage_address(state.mstate.stack[-2])
            return Result(state.environment.active_function_name, _index_owner=storage_address)

        return None

    def _retrieve_storage_address(self, bitvec: BitVec) -> Optional[int]:
        """ Helper function to retrieve the *storage_address* attribute from a BitVec instance. """
        for annotation in bitvec.annotations:
            if isinstance(annotation, Storage):
                return annotation.storage_address
        return None
