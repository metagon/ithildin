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

    pre_hooks = ['ADD', 'JUMPDEST', 'JUMPI', 'SHA3']
    post_hooks = ['CALLER', 'SHA3', 'SLOAD']

    def __init__(self):
        super().__init__()
        self.forward_next = None
        self.concrete_memory_cache = set()

    def _analyze(self, state: GlobalState, prev_state: Optional[GlobalState] = None) -> Optional[Result]:
        if prev_state.instruction['opcode'] == 'CALLER':
            state.mstate.stack[-1].annotate(Caller())
        elif prev_state.instruction['opcode'] == 'SHA3':
            # Forward annotations for concrete and symbolic values
            self._sha3_postprocess(state)
        elif prev_state.instruction['opcode'] == 'SLOAD':
            # Forward annotations
            self._sload_postprocess(state, prev_state)

        if state.instruction['opcode'] == 'JUMPDEST':
            # Function entrypoint operations
            self._jumpdest_preprocess(state)
        elif state.instruction['opcode'] == 'ADD':
            # Update concrete memory cache elements
            self._add_preprocess(state)
        elif state.instruction['opcode'] == 'SHA3':
            # Check if there are annotations for concrete values to be forwarded
            self._sha3_preprocess(state)
        elif state.instruction['opcode'] == 'JUMPI' and {HashedCaller(), HashedRole()}.issubset(state.mstate.stack[-2].annotations):
            value = self._retrieve_value(state.mstate.stack[-2].annotations)
            if value is not None:
                log.info('Value = %s', hex(value))
            self.concrete_memory_cache.clear()
            return Result(state.environment.active_function_name)

    def _jumpdest_preprocess(self, state: GlobalState):
        """
        When the JUMPDEST opcode is present it may indicate the start of a function. Since we aim at
        detecting the function that checks wether an address has a specific role assigned, we first check
        if at least two elements are present in the stack. If that's the case, we continue with checking
        if either the top or second element in the stack is annotated with *Caller*. In that case,
        we assume that the opposite element is the role, and annotate that accordingly. In case the role
        element is concrete, we mark it in the memory cache for later, because annotations do not survive
        memory reads/writes in that case.
        """
        if len(state.mstate.stack) <= 1:
            return
        if Caller() in state.mstate.stack[-1].annotations:
            if state.mstate.stack[-2].symbolic:
                state.mstate.stack[-2].annotate(Role())
            else:
                self.concrete_memory_cache.add(state.mstate.stack[-2].value)
        elif Caller() in state.mstate.stack[-2].annotations:
            if state.mstate.stack[-1].symbolic:
                state.mstate.stack[-1].annotate(Role())
            else:
                self.concrete_memory_cache.add(state.mstate.stack[-1].value)

    def _sha3_preprocess(self, state: GlobalState):
        """
        Helper function that scans the memory for words that are concrete values, checks
        if their value exists in the cache, and in that case marks that value to be forwarded
        (later as an annotation) after the SHA3 operation gets executed.

        This is a hack for forwarding annotations of concrete values since once the Laser EVM stores
        a (concrete) value in memory, only the bytes get stored (not as BitVec instances), and all the
        annotations get lost.
        """
        word_len = 32
        lo = state.mstate.stack[-1].value
        hi = state.mstate.stack[-2].value
        if hi - lo < word_len:
            return None
        for i in range(lo, hi, word_len):
            data_list = [
                b if isinstance(b, BitVec) else symbol_factory.BitVecVal(b, 8)
                for b in state.mstate.memory[i: i + word_len]
            ]
            data = simplify(Concat(data_list))
            if data.symbolic is False and data.value in self.concrete_memory_cache:
                self.forward_next = data.value
                self.concrete_memory_cache.remove(data.value)

    def _sha3_postprocess(self, state: GlobalState):
        """
        Helper function for forwarding annotations after the SHA3 operation has executed.
        It first checks if the *forward_next* variable has any value, which indicates that a
        concrete value has been hashed. In that case we forward the *HashedRole* annotation
        together with said value.

        In case the hashed element is not concrete, we forward *HashedRole* and *HashedCaller*
        for elements that have been annotated with *Role* and *Caller* respectively.
        """
        if self.forward_next is not None:
            state.mstate.stack[-1].annotate(HashedRole(self.forward_next))
            self.forward_next = None
            if state.mstate.stack[-1].symbolic is False:
                self.concrete_memory_cache.add(state.mstate.stack[-1].value)
        if Role() in state.mstate.stack[-1].annotations:
            value = self._retrieve_value(state.mstate.stack[-1].annotations)
            state.mstate.stack[-1].annotate(HashedRole(value))
        if Caller() in state.mstate.stack[-1].annotations:
            state.mstate.stack[-1].annotate(HashedCaller())

    def _add_preprocess(self, state: GlobalState):
        """
        Sometimes role elements are stored in structs and we need to update the cached memory
        elements to reflect the index in those structs.
        """
        if {Role(), HashedRole()} & state.mstate.stack[-1].annotations:
            inc = state.mstate.stack[-2].value
            self.concrete_memory_cache = {v + inc for v in self.concrete_memory_cache}
        elif {Role(), HashedRole()} & state.mstate.stack[-2].annotations:
            inc = state.mstate.stack[-1].value
            self.concrete_memory_cache = {v + inc for v in self.concrete_memory_cache}

    def _sload_postprocess(self, state: GlobalState, prev_state: GlobalState):
        """
        If we load something from memory and both the *HashedCaller* as well as the *HashedRole*
        annotations are present, we annotate the next state with the same annotations because
        they wouldn't be forwarded otherwise.
        """
        if {HashedCaller(), HashedRole()}.issubset(prev_state.mstate.stack[-1].annotations):
            value = self._retrieve_value(prev_state.mstate.stack[-1].annotations)
            state.mstate.stack[-1].annotate(HashedCaller())
            state.mstate.stack[-1].annotate(HashedRole(value))

    def _retrieve_value(self, annotations: set):
        for annotation in annotations:
            if isinstance(annotation, Role):
                return annotation.value
