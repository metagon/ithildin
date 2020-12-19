import logging
import re
import time

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Text, Union

from ithildin.loader.contract_loader import FileLoader, Web3Loader
from ithildin.util.logic import xor

from mythril.exceptions import UnsatError
from mythril.laser.ethereum import svm
from mythril.laser.ethereum.cfg import Constraints, Edge, Node
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.support.loader import DynLoader
from mythril.support.model import get_model

log = logging.getLogger(__name__)


class AnalysisStrategy(ABC):
    """
    Base class for contract analysis strategies. Subclasses should be instantiated using one of the classmethods:

    * from_file_loader
    * from_web3_loader

    When creating a new analysis strategy by subclassing this base class, override the *_analyze(...)* method.
    """

    def __init__(self,
                 creation_code: Optional[Text] = None,
                 target_address: Optional[Text] = None,
                 dyn_loader: Optional[DynLoader] = None):
        create_mode = creation_code is not None
        existing_mode = target_address is not None and dyn_loader is not None
        assert xor(create_mode, existing_mode), ('Either the contract\'s creation_code or the target_address '
                                                 'together with a dyn_loader instance have to be provided.')
        if existing_mode:
            self.laser = svm.LaserEVM(dyn_loader)
        else:
            self.laser = svm.LaserEVM()
        self.creation_code = creation_code
        self.target_address = target_address
        self.dyn_loader = dyn_loader

    @classmethod
    def from_file_loader(cls, file_loader: FileLoader):
        log.debug('Creating %s instance from file loader.', cls.__name__)
        contract = file_loader.contract()
        return cls(creation_code=contract.creation_disassembly.bytecode)

    @classmethod
    def from_web3_loader(cls, web3_loader: Web3Loader):
        log.debug('Creating %s instance from Web3 loader.', cls.__name__)
        return cls(target_address=web3_loader.address, dyn_loader=web3_loader.dyn_loader)

    def execute(self) -> Optional[Union[List[Text], List[int]]]:
        """
        Wrapper method for executing the analysis strategy.
        Symbolic execution is performed before the execution of the internal analysis method (*_analyze(...)*).

        This is what should be called by the client, and the actual implementation should be written in *_analyze(...)*.
        """
        log.info('Running symbolic execution...')
        start_time = time.time()
        if self.creation_code:
            self.laser.sym_exec(creation_code=self.creation_code, contract_name="Unknown")
        elif self.target_address and self.dyn_loader:
            world_state = WorldState()
            world_state.accounts_exist_or_load(self.target_address, self.dyn_loader)
            self.laser.sym_exec(world_state=world_state, target_address=int(self.target_address, 16))
        else:
            raise AttributeError('Symbolic execution cannot run without either the creation bytecode or a dynamic loader')
        end_time = time.time()
        log.info('Symbolic execution finished in %.2f seconds.', end_time - start_time)
        log.info('Executing analysis strategy.')
        storage_addresses = self._analyze()
        log.debug('Found the following storage addresses: %s', str(storage_addresses))
        if self.target_address and self.dyn_loader:
            return [self.dyn_loader.read_storage(self.target_address, i) for i in storage_addresses]
        else:
            return list(storage_addresses)

    @abstractmethod
    def _analyze(self) -> Optional[Set[int]]:
        """
        Actual implementation of the analysis strategy. Override this when creating a new AnalysisStrategy subclass.
        """
        pass

    def _is_unsat(self, proposition: Constraints) -> bool:
        """
        Checks if the *proposition* is unsatisfiable.

        Parameters
        ----------
        proposition: Constraints
            The proposition to check.

        Returns
        -------
        True if the proposition is unsat, False otherwise.
        """
        try:
            model = get_model(proposition)
            log.debug('Violation found...')
            log.debug('### BEGIN DECLARATIONS ###')
            for d in model.decls():
                log.debug("<DECL %s = %s>", d.name(), re.sub(r'\s{2,}', ' ', str(model[d]).replace('\n', ' ')))
            log.debug('### END DECLARATIONS ###')
            return False
        except UnsatError:
            return True

    def _get_outgoing_edges(self, node_uid: int) -> List[Edge]:
        """
        Helper function that returns all outgoing edges from the given node.

        Parameters
        ----------
        node_uid: int
            The unique ID of the node in question.
        """
        return [e for e in self.laser.edges if e.node_from == node_uid]

    def _opcode_follows(self, node_uid: int, opcode: Text) -> bool:
        """
        Helper function to check whether an *opcode* is contained in a node that immediately
        follows the node with UID *node_uid*.

        Parameters
        ----------
        node_uid: int
            The unique ID of the node in the symbolic graph.
        opcode: Text
            The name of the opcode to look for (e.g. 'EQ', 'REVERT').
        """
        outgoing_edges = self._get_outgoing_edges(node_uid)
        for edge in outgoing_edges:
            for state in self.laser.nodes[edge.node_to].states:
                if state.instruction['opcode'] == opcode:
                    return True
        return False
