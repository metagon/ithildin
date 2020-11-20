import logging

from mythril.laser.ethereum.cfg import Node
from typing import Dict, Optional, Set, Text

from sc3a.analysis.base import AnalysisStrategy

log = logging.getLogger(__name__)


class SingleOwnerStrategy(AnalysisStrategy):

    def _analyze(self, nodes: Dict[int, Node]) -> Optional[Set[Text]]:
        log.info('Analyzing nodes of symbolic execution')
        potential_storage_addresses = set()
        for nidx, node in nodes.items():
            caller = None
            storage_item = None
            storage_address = None
            for sidx, state in enumerate(node.states):
                if state.instruction['opcode'] == 'CALLER':
                    # We store the caller item, which sits at the head of the stack
                    # in the next state in case it is a symbol.
                    caller = node.states[sidx + 1].mstate.stack[-1]
                    log.debug('Found CALLER symbol "%s" in <node=%i, state=%i>', caller, nidx, sidx)
                elif state.instruction['opcode'] == 'SLOAD':
                    # We store the storage address from the current stack and the storage
                    # item from the next stack in case the latter is a symbol.
                    storage_item = node.states[sidx + 1].mstate.stack[-1]
                    storage_address = state.mstate.stack[-1]
                    log.debug('Found SLOAD instruction in <node=%i, state=%i>', nidx, sidx)
                elif state.instruction['opcode'] == 'EQ':
                    # The top two items in the stack are being compared. We first extract
                    # the two items into stack_0 and stack_1, and check if both are symbols.
                    # Next, we check if the two items are always equal to the two items that
                    # we have previously stored. If that is the case, we keep the storage
                    # address that we got from the SLOAD operation.
                    if storage_item is None or caller is None:
                        # SLOAD and CALLER haven't been called within the same node
                        continue
                    log.debug('Found EQ instruction in <node=%i, state=%i>', nidx, sidx)
                    stack_0 = state.mstate.stack[-1]
                    stack_1 = state.mstate.stack[-2]
                    # Head is the caller and second element is the storage item
                    proposition_0 = node.constraints
                    proposition_0.append(stack_0 != caller)
                    proposition_0.append(stack_1 != storage_item)
                    # Head is the storage item and second element is the caller
                    proposition_1 = node.constraints
                    proposition_1.append(stack_0 != storage_item)
                    proposition_1.append(stack_1 != caller)
                    # If either proposition is unsat we keep the storage address
                    if self._is_unsat(proposition_0) or self._is_unsat(proposition_1):
                        potential_storage_addresses.add(storage_address)
        log.info(('Found %i potential storage addresses that might '
                  'contain administrator accounts'), len(potential_storage_addresses))
        return potential_storage_addresses
