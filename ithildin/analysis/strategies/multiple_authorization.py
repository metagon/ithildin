from typing import Optional, Type
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt import BitVec

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.analysis import Result


class Storage:

    def __init__(self, index):
        self.index = index

    def __hash__(self):
        return hash((type(self), self.index))

    def __eq__(self, other: 'Storage'):
        return self.index == other.index


class Comparison:

    def __init__(self, index_x: int, index_y: int):
        self.index_x = index_x
        self.index_y = index_y

    def __hash__(self):
        return hash((type(self), self.index_x, self.index_y))

    def __eq__(self, other: 'Comparison'):
        return self.index_x == other.index_x and self.index_y == other.index_y


class MultipleAuthorization(AnalysisStrategy):

    pattern_name = 'MULTIPLE_AUTHORIZATION'
    report_title = 'Multiple Authorization'
    report_description = 'TODO'

    pre_hooks = ['JUMPI', 'SSTORE']
    post_hooks = ['SLOAD', 'LT', 'GT']

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state and prev_state.instruction['opcode'] == 'SLOAD' and prev_state.mstate.stack[-1].symbolic is False:
            index = prev_state.mstate.stack[-1].value
            if index < 0x100000000:
                state.mstate.stack[-1].annotate(Storage(index))
        elif prev_state and prev_state.instruction['opcode'] in {'LT', 'GT'}:
            s0_store = self._retrieve_taint(prev_state.mstate.stack[-1], Storage)
            s1_store = self._retrieve_taint(prev_state.mstate.stack[-2], Storage)
            if s0_store and s1_store and s0_store.index is not None and s1_store.index is not None:
                state.mstate.stack[-1].annotations.discard(Storage(s0_store.index))
                state.mstate.stack[-1].annotations.discard(Storage(s1_store.index))
                state.mstate.stack[-1].annotate(Comparison(s0_store.index, s1_store.index))

        if state.instruction['opcode'] == 'JUMPI':
            s1_comp = self._retrieve_taint(state.mstate.stack[-2], Comparison)
            if s1_comp is not None:
                return Result(state.environment.active_function_name)

        return None

    def _retrieve_taint(self, bitvec: BitVec, taint_type: Type):
        for taint in bitvec.annotations:
            if isinstance(taint, taint_type):
                return taint
        return None
