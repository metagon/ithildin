from enum import Enum
from typing import Optional

from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt.bitvec import BitVec

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.analysis import Result


class Actor(Enum):
    SENDER = 1
    OWNER = 2


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


class Equality:
    """ Class to be used as annotation for EQ elements. """

    def __init__(self, actor: Actor):
        self.actor = actor

    def __hash__(self):
        return hash((type(self), self.actor))

    def __eq__(self, other: 'Equality'):
        return self.actor == other.actor


class Ownership(AnalysisStrategy):

    pattern_name = 'OWNERSHIP'
    report_title = 'Ownership'
    report_description = ('This pattern aims at restricting functions to specific addresses. For example '
                          'the owner of the contract is specified in the constructor and only that account '
                          'is allowed to access a function and change the contract\'s state.')

    pre_hooks = ['EQ', 'JUMPI']
    post_hooks = ['CALLER', 'SLOAD']

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state and prev_state.instruction['opcode'] == 'CALLER':
            state.mstate.stack[-1].annotate(Caller())
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD' and prev_state.mstate.stack[-1].symbolic is False:
            index = prev_state.mstate.stack[-1].value
            if index < 0x100000000:
                # Restrict memorizing storage keys that result from some sort of hashing by
                # assuming that no contract would ever have 2^32 storage variables LOL.
                state.mstate.stack[-1].annotate(Storage(index))

        if state.instruction['opcode'] == 'EQ':
            # Check if both top stack elemnts have been annotated with Caller and Storage,
            # in which case we annotate both elements with the Equality annotation, and
            # their respective actors.
            if self._has_annotation(state.mstate.stack[-1], Storage) and Caller() in state.mstate.stack[-2].annotations:
                state.mstate.stack[-1].annotate(Equality(Actor.OWNER))
                state.mstate.stack[-2].annotate(Equality(Actor.SENDER))
            elif Caller() in state.mstate.stack[-1].annotations and self._has_annotation(state.mstate.stack[-2], Storage):
                state.mstate.stack[-1].annotate(Equality(Actor.SENDER))
                state.mstate.stack[-2].annotate(Equality(Actor.OWNER))
        elif state.instruction['opcode'] == 'JUMPI' and self._is_target_jumpi(state):
            storage_address = self._retrieve_storage_address(state.mstate.stack[-2])
            return Result(state.environment.active_function_name, _index_owner=storage_address)

        return None

    def _is_target_jumpi(self, state: GlobalState) -> bool:
        """
        Helper method for checking if the JUMPI contains the targeted annotations.

        Returns
        -------
        True if the second stack element contains two annotations of type Equality with attributes
        'owner' and 'sender', False otherwise.
        """
        return {Equality(Actor.OWNER), Equality(Actor.SENDER)}.issubset(state.mstate.stack[-2].annotations)

    def _retrieve_storage_address(self, bitvec: BitVec) -> Optional[int]:
        """ Helper function to retrieve the *storage_address* attribute from a BitVec instance. """
        for annotation in bitvec.annotations:
            if isinstance(annotation, Storage):
                return annotation.storage_address
        return None
