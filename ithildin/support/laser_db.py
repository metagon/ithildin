import logging
import time

from typing import Optional, Text

from .singleton import Singleton

from mythril.laser.ethereum import svm
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.support.loader import DynLoader

log = logging.getLogger(__name__)


class LaserDB(metaclass=Singleton):
    """ The class is meant to serve the sole purpose of caching symbolic execution graphs. """

    def __init__(self):
        self._db = {}

    def sym_exec(self,
                 creation_code: Optional[Text] = None,
                 target_address: Optional[Text] = None,
                 dyn_loader: Optional[DynLoader] = None) -> svm.LaserEVM:
        """
        This function first checks, depending on which arguments were provided, if a laser
        instance exists in the hash table. If *creation_code* is given, the function will search
        with the *creation_code* as the key, otherwise if *target_address* is given, that one
        will be used as the lookup key. In case no laser instance is found, this function will
        create a new instance, run symbolic execution, store the laser instance in the hash
        table and return the laser instance.
        """
        if creation_code is not None and target_address is None:
            if creation_code not in self._db:
                log.info('Running symbolic execution in creation mode...')
                laser = svm.LaserEVM()
                start_time = time.time()
                laser.sym_exec(creation_code=creation_code, contract_name="Unknown")
                log.info('Symbolic execution finished in %.2f seconds.', time.time() - start_time)
                self._db[creation_code] = laser
            return self._db[creation_code]
        elif creation_code is None and target_address is not None:
            assert dyn_loader is not None, "Dynamic Loader has not been provided"
            if target_address not in self._db:
                log.info('Running symbolic execution in existing mode...')
                laser = svm.LaserEVM(dyn_loader)
                world_state = WorldState()
                world_state.accounts_exist_or_load(target_address, dyn_loader)
                start_time = time.time()
                laser.sym_exec(world_state=world_state, target_address=int(target_address, 16))
                log.info('Symbolic execution finished in %.2f seconds.', time.time() - start_time)
                self._db[target_address] = laser
            return self._db[target_address]
        else:
            raise AttributeError('Either creation_code or target_address needs to be provided')
