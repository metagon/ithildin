import logging
from typing import Optional, Set, List, Text

from mythril.ethereum.evmcontract import EVMContract
from mythril.laser.ethereum import svm

from sc3a.analysis.base import AnalysisStrategy

log = logging.getLogger(__name__)


class SingleOwnerStrategy(AnalysisStrategy):

    def __init__(self, contract: EVMContract):
        super().__init__(contract)
        log.debug('SingleOwner strategy has been initialized')

    def execute(self) -> Optional[List[Text]]:
        log.info('Running symbolic execution')
        laser = svm.LaserEVM()
        laser.sym_exec(creation_code=self.contract.creation_disassembly.bytecode,
                       contract_name="Unknown")
        storage_addresses = self._analyze(laser.nodes)
        return list(storage_addresses)

    def _analyze(self, nodes: dict) -> Optional[Set[Text]]:
        log.info('Analyzing nodes of symbolic execution')
        potential_storage_addresses = set()
        for i, node in nodes.items():
            saddr = None
            contains_caller = False
            for state in node.states:
                if state.instruction['opcode'] == 'CALLER':
                    # CALLER has been called, which pushes the message sender's address
                    # on the stack.
                    log.debug('Found CALLER instruction in node: %s', i)
                    contains_caller = True
                if state.instruction['opcode'] == 'SLOAD':
                    # We temporarily memorize the storage lookup address for later.
                    log.debug('Found SLOAD instruction in node: %i', i)
                    saddr = state.mstate.stack[-1]
                if state.instruction['opcode'] == 'EQ':
                    # The program checks if the top two words on the stack are equal, after
                    # loading something from storage as well as the message sender.
                    # This means that it's highly likely that the program currently checks
                    # if the message sender is authorized to perform an operation.
                    # We store the previously temporarily memorized saddr to a collection of
                    # possible address spaces, where the "owner" of the contract might be stored.
                    log.debug('Found EQ instruction in node: %i', i)
                    if contains_caller and saddr is not None:
                        log.debug('Found potential storage address: %s', saddr)
                        potential_storage_addresses.add(saddr)
        log.info('Found %i potential storage addresses that might \
                  contain administrator accounts', len(potential_storage_addresses))
        return potential_storage_addresses
