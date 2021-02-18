from enum import Enum
from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt.bitvec import BitVec

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.analysis import Result


class Element(Enum):
    NUMBER = 1
    STORAGE = 2


class Comparison:
    """ Class to be used as annotation for comparison elements. """

    def __init__(self, item):
        self.item = item

    def __hash__(self):
        return hash((type(self), self.item))

    def __eq__(self, other):
        return self.item == other.item


class Storage:
    """ Class to be used for SLOAD elements. """

    def __init__(self, storage_address: Optional[int] = None):
        self.storage_address = storage_address

    def __hash__(self):
        return hash((type(self), self.storage_address))

    def __eq__(self, other):
        return self.storage_address == other.storage_address


class BlockNumber:
    """ Class to be used as annotation for NUMBER elements. """

    def __hash__(self):
        return hash(type(self))

    def __eq__(self, other):
        return isinstance(other, BlockNumber)


class XConfirmation(AnalysisStrategy):

    pattern_name = 'X_CONFIRMATION'
    report_title = 'X-Confirmation (Block Count)'
    report_description = ('This pattern protects functions from being executed unless a condition related to the '
                          'current block number is met. For example one might want to wait for a certain number '
                          'of blocks to have passed before a transaction is marked as valid or confirmed.')

    pre_hooks = ['JUMPI', 'EQ', 'LT', 'GT']
    post_hooks = ['NUMBER', 'SLOAD']

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state and prev_state.instruction['opcode'] == 'NUMBER':
            state.mstate.stack[-1].annotate(BlockNumber())
        elif prev_state and prev_state.instruction['opcode'] == 'SLOAD':
            state.mstate.stack[-1].annotate(Storage(prev_state.mstate.stack[-1].value))

        if state.instruction['opcode'] in {'EQ', 'LT', 'GT'}:
            if BlockNumber() in state.mstate.stack[-1].annotations and self._has_annotation(state.mstate.stack[-2], Storage):
                state.mstate.stack[-1].annotate(Comparison(Element.NUMBER))
                state.mstate.stack[-2].annotate(Comparison(Element.STORAGE))
            elif self._has_annotation(state.mstate.stack[-1], Storage) and BlockNumber() in state.mstate.stack[-2].annotations:
                state.mstate.stack[-1].annotate(Comparison(Element.STORAGE))
                state.mstate.stack[-2].annotate(Comparison(Element.NUMBER))
        elif state.instruction['opcode'] == 'JUMPI' and self._is_target_jumpi(state):
            storage_address = self._retrieve_storage_address(state.mstate.stack[-2])
            return Result(state.environment.active_function_name, _index_block_condition=storage_address)

        return None

    def _is_target_jumpi(self, state: GlobalState) -> bool:
        """
        Helper method for checking if the second element on the stack before a JUMPI instruction
        contains the targeted annotations, i.e. two annotations of type Comparison with elements
        NUMBER and STORAGE.

        Returns
        -------
        True if the annotations and their elements are present, False otherwise.
        """
        return {Comparison(Element.NUMBER), Comparison(Element.STORAGE)}.issubset(state.mstate.stack[-2].annotations)

    def _retrieve_storage_address(self, bitvec: BitVec) -> Optional[int]:
        """ Helper function to retrieve the *storage_address* attribute from a BitVec instance. """
        for annotation in bitvec.annotations:
            if isinstance(annotation, Storage):
                return annotation.storage_address
        return None
