from enum import Enum
from typing import Optional
from mythril.laser.ethereum.state.global_state import GlobalState

from ithildin.analysis.base import AnalysisStrategy
from ithildin.model.report import Result


class Item(Enum):
    NUMBER = 1
    STORAGE = 2


class Comparison:

    def __init__(self, item):
        self.item = item


class Storage:

    def __init__(self, storage_address=None):
        self.storage_address = storage_address


class BlockNumber:

    def __init__(self, persist_to_world_state=False):
        self.persist_to_world_state = persist_to_world_state


class XConfirmation(AnalysisStrategy):

    OPCODE_FLAG_TARGET = 0b111

    pattern_name = 'X_CONFIRMATION'
    report_title = 'X-Confirmation (Block Count)'
    report_description = ('This pattern protects functions from being executed unless a condition related to the '
                          'current block number is met. For example one might want to wait for a certain number '
                          'of blocks to have passed before a transaction is marked as valid or confirmed.')

    pre_hooks = ['JUMPI', 'EQ', 'LT', 'GT']
    post_hooks = ['NUMBER', 'SLOAD']

    def _analyze(self, state: GlobalState) -> Optional[Result]:
        if self._prev_opcode(state) == 'NUMBER':
            state.mstate.stack[-1].annotate(BlockNumber())
        elif self._prev_opcode(state) == 'SLOAD':
            state.mstate.stack[-1].annotate(Storage())

        if state.instruction['opcode'] in {'EQ', 'LT', 'GT'}:
            if self._has_annotation(state.mstate.stack[-1], BlockNumber) and self._has_annotation(state.mstate.stack[-2], Storage):
                state.mstate.stack[-1].annotate(Comparison(Item.NUMBER))
                state.mstate.stack[-2].annotate(Comparison(Item.STORAGE))
            elif self._has_annotation(state.mstate.stack[-1], Storage) and self._has_annotation(state.mstate.stack[-2], BlockNumber):
                state.mstate.stack[-1].annotate(Comparison(Item.STORAGE))
                state.mstate.stack[-2].annotate(Comparison(Item.NUMBER))
        elif state.instruction['opcode'] == 'JUMPI' and self._is_target_jumpi(state):
            return Result(state.environment.active_function_name)

        return None

    def _is_target_jumpi(self, state: GlobalState) -> bool:
        item_flags = 0b00
        for annotation in state.mstate.stack[-2].annotations:
            if isinstance(annotation, Comparison):
                item_flags |= 0b01 if annotation.item == Item.NUMBER else 0
                item_flags |= 0b10 if annotation.item == Item.STORAGE else 0
        return item_flags == 0b11
