import logging

from ethereum import utils
from typing import Optional

from mythril.laser.smt import symbol_factory, simplify, BitVec, Concat
from mythril.laser.ethereum.keccak_function_manager import keccak_function_manager
from mythril.laser.ethereum.state.global_state import GlobalState

from ithildin.analysis.base import AnalysisStrategy
from ithildin.report.analysis import Result

log = logging.getLogger(__name__)


class Caller:
    """Caller annotation."""

    def __eq__(self, other: 'Caller'):
        return isinstance(other, Caller)

    def __hash__(self):
        return hash(type(self))


class HashedCaller():
    """Annotation to be used for Caller elements that were hashed for lookup. """

    def __eq__(self, other: 'HashedCaller'):
        return isinstance(other, HashedCaller)

    def __hash__(self):
        return hash(type(self))


class Role:
    """Role annotation. """

    def __init__(self, value=None):
        self.value = value

    def __eq__(self, other: 'Role'):
        return isinstance(other, Role)

    def __hash__(self):
        return hash(type(self))


class HashedRole(Role):
    """Annotation to be used for Role elements that were hashed for lookup. """

    def __eq__(self, other: 'HashedRole'):
        return isinstance(other, HashedRole)

    def __hash__(self):
        return hash(type(self))


class RoleBasedAccessControl(AnalysisStrategy):

    pattern_name = 'ROLES'
    report_title = 'Role Based Access Control'
    report_description = ('TODO')

    pre_hooks = ['JUMPDEST', 'JUMPI', 'SHA3', 'ADD']
    post_hooks = ['CALLER', 'SHA3', 'SLOAD']

    concrete_vals = set()
    forward_next = None

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state.instruction['opcode'] == 'CALLER':
            state.mstate.stack[-1].annotate(Caller())
        elif prev_state.instruction['opcode'] == 'SHA3':
            if self.forward_next is not None:
                state.mstate.stack[-1].annotate(HashedRole(self.forward_next))
                self.forward_next = None
                if state.mstate.stack[-1].symbolic is False:
                    self.concrete_vals.add(state.mstate.stack[-1].value)
            if Role() in state.mstate.stack[-1].annotations:
                value = self._retrieve_value(state.mstate.stack[-1].annotations)
                state.mstate.stack[-1].annotate(HashedRole(value))
            if Caller() in state.mstate.stack[-1].annotations:
                state.mstate.stack[-1].annotate(HashedCaller())
        elif prev_state.instruction['opcode'] == 'SLOAD' and {HashedCaller(), HashedRole()}.issubset(prev_state.mstate.stack[-1].annotations):
            value = self._retrieve_value(prev_state.mstate.stack[-1].annotations)
            state.mstate.stack[-1].annotate(HashedCaller())
            state.mstate.stack[-1].annotate(HashedRole(value))

        if state.instruction['opcode'] == 'JUMPDEST' and len(state.mstate.stack) > 1:
            if Caller() in state.mstate.stack[-1].annotations:
                if state.mstate.stack[-2].symbolic:
                    state.mstate.stack[-2].annotate(Role())
                else:
                    self.concrete_vals.add(state.mstate.stack[-2].value)
            elif Caller() in state.mstate.stack[-2].annotations:
                if state.mstate.stack[-1].symbolic:
                    state.mstate.stack[-1].annotate(Role())
                else:
                    self.concrete_vals.add(state.mstate.stack[-1].value)
        elif state.instruction['opcode'] == 'ADD':
            if {Role(), HashedRole()} & state.mstate.stack[-1].annotations:
                inc = state.mstate.stack[-2].value
                self.concrete_vals = {v + inc for v in self.concrete_vals}
            elif {Role(), HashedRole()} & state.mstate.stack[-2].annotations:
                inc = state.mstate.stack[-1].value
                self.concrete_vals = {v + inc for v in self.concrete_vals}
        elif state.instruction['opcode'] == 'SHA3':
            lo = state.mstate.stack[-1].value
            hi = state.mstate.stack[-2].value
            if hi - lo < 32:
                return None
            for i in range(lo, hi, 32):
                data_list = [
                    b if isinstance(b, BitVec) else symbol_factory.BitVecVal(b, 8)
                    for b in state.mstate.memory[i:i+32]
                ]
                data = simplify(Concat(data_list))
                if data.symbolic is False and data.value in self.concrete_vals:
                    self.forward_next = data.value
                    self.concrete_vals.remove(data.value)
        elif state.instruction['opcode'] == 'JUMPI' and {HashedCaller(), HashedRole()}.issubset(state.mstate.stack[-2].annotations):
            value = self._retrieve_value(state.mstate.stack[-2].annotations)
            if value is not None:
                log.info('Value = %s', hex(value))
            return Result(state.environment.active_function_name)

    def _retrieve_value(self, annotations: set):
        for annotation in annotations:
            if isinstance(annotation, Role):
                return annotation.value
